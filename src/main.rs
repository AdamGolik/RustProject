use std::env;

use actix_web::{get, middleware::Logger, web, App, HttpResponse, HttpServer, Responder};
use dotenv::dotenv;
use env_logger::Env;
use middleware::jwt::JwtMiddleware;
use migration::{Migrator, MigratorTrait};
use sea_orm::{Database, DatabaseConnection};
//mods
mod controller;
mod entity;
mod middleware;
#[get("/")]
async fn hello() -> impl Responder {
    HttpResponse::Ok().body("Hello world!")
}
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok().expect("create .env file");
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    let db_url = env::var("DATABASE_URL").expect("set your db url in .env");
    let db: DatabaseConnection = Database::connect(&db_url)
        .await
        .expect("Faild to connect to the database");

    // Run the 'up' migration to create the tables again
    match Migrator::up(&db, None).await {
        Ok(_) => println!("Database migrations ran successfully."),
        Err(e) => {
            eprintln!("Failed to apply 'up' migration: {}", e);
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Migration up failed",
            ));
        }
    }
    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(db.clone())) // Share database connection with the app
            .wrap(Logger::new("%a %r %s %b %D %U %{User-Agent}i"))
            .service(hello)
            .service(controller::user::register)
            .service(controller::user::login)
            .service(
                web::scope("/user")
                    .wrap(JwtMiddleware)
                    .service(controller::user::settings)
                    .service(controller::user::update)
                    .service(controller::user::delete),
            )
            .service(
                web::scope("/clients")
                    .wrap(JwtMiddleware)
                    .service(controller::client::add_client)
                    .service(controller::client::get_client)
                    .service(controller::client::get_clients)
                    .service(controller::client::update_client)
                    .service(controller::client::delete_client)
                    .service(controller::client::get_clients_by_date_range),
            )
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}

