use crate::entity::user::{self, ActiveModel, Entity, Model};
use crate::middleware::jwt::{generate_jwt, Claims};
use actix_web::{delete, get, post, put, web, HttpRequest, HttpResponse, Responder};
use bcrypt::{hash, verify, DEFAULT_COST};
use jsonwebtoken::{decode, DecodingKey, Validation};
use sea_orm::ActiveValue::Set;
use sea_orm::{ActiveModelTrait, ColumnTrait, DbConn, EntityTrait, IntoActiveModel, QueryFilter};
use uuid::Uuid;

#[post("/register")]
pub async fn register(db: web::Data<DbConn>, req: web::Json<user::Controller>) -> impl Responder {
    // Check if user already exists
    let existing_user = Entity::find()
        .filter(user::Column::Email.eq(&req.email))
        .one(db.get_ref())
        .await;

    if let Ok(Some(_)) = existing_user {
        return HttpResponse::BadRequest().body("User already exists");
    }

    // Hash the password
    let hashed_password = match hash(&req.password, DEFAULT_COST) {
        Ok(pwd) => pwd,
        Err(_) => return HttpResponse::InternalServerError().body("Password hashing failed"),
    };

    // Create the new user
    let new_user = ActiveModel {
        uuid: Set(Uuid::new_v4()), // ✅ generate a UUID
        name: Set(req.name.clone()),
        lastname: Set(req.lastname.clone()),
        email: Set(req.email.clone()),
        password: Set(hashed_password),
        ..Default::default()
    };

    // Insert into database
    match Entity::insert(new_user).exec(db.get_ref()).await {
        Ok(_) => HttpResponse::Created().json(serde_json::json!({
            "message": "User created successfully",
        })),
        Err(e) => {
            eprintln!("Database error: {}", e);
            HttpResponse::InternalServerError().body("Database error")
        }
    }
}

#[post("/login")]
pub async fn login(db: web::Data<DbConn>, req: web::Json<user::Controller>) -> impl Responder {
    let user_result = Entity::find()
        .filter(user::Column::Email.eq(&req.email))
        .one(&**db)
        .await;
    match user_result {
        Ok(Some(user)) => match verify(&req.password, &user.password) {
            Ok(true) => {
                let token = generate_jwt(&user.uuid.to_string());
                HttpResponse::Ok().json(serde_json::json!({
                    "token": token,
                }))
            }
            Ok(false) => HttpResponse::Unauthorized().body("Invalid credentials"),
            Err(_) => HttpResponse::InternalServerError().body("Password verification failed"),
        },
        Ok(None) => HttpResponse::NotFound().body("User not found"),
        Err(_) => HttpResponse::InternalServerError().body("Database error"),
    }
}

#[get("/account")]
pub async fn settings(db: web::Data<DbConn>, req: HttpRequest) -> impl Responder {
    let auth_header = req
        .headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok());

    if let Some(auth_header) = auth_header {
        if let Some(token) = auth_header.strip_prefix("Bearer ") {
            let jwt_secret = std::env::var("JWT_SECRET").unwrap_or_else(|_| "secret".into());

            let token_data = decode::<Claims>(
                token,
                &DecodingKey::from_secret(jwt_secret.as_bytes()),
                &Validation::default(),
            );

            if let Ok(token_data) = token_data {
                let user_id_str = token_data.claims.sub;

                // Zakładam, że `uuid` jest używane jako typ klucza
                let user_uuid = match Uuid::parse_str(&user_id_str) {
                    Ok(id) => id,
                    Err(_) => return HttpResponse::BadRequest().body("Invalid user ID in token"),
                };

                match Entity::find_by_id(user_uuid).one(&**db).await {
                    Ok(Some(user)) => HttpResponse::Ok().json(serde_json::json!({ "user": user })),
                    Ok(None) => HttpResponse::NotFound().body("User not found"),
                    Err(_) => HttpResponse::InternalServerError().body("Database error"),
                }
            } else {
                HttpResponse::Unauthorized().body("Invalid token")
            }
        } else {
            HttpResponse::Unauthorized().body("Missing Bearer prefix")
        }
    } else {
        HttpResponse::Unauthorized().body("Missing Authorization header")
    }
}

#[put("/account")]
pub async fn update(
    db: web::Data<DbConn>,
    req: HttpRequest,
    user: web::Json<user::Controller>,
) -> impl Responder {
    // Authorization header
    let auth_header = match req
        .headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
    {
        Some(h) => h,
        None => return HttpResponse::Unauthorized().body("Missing Authorization header"),
    };

    // Strip Bearer
    let token = match auth_header.strip_prefix("Bearer ") {
        Some(t) => t,
        None => return HttpResponse::Unauthorized().body("Invalid token format"),
    };

    // Decode JWT
    let token_data = match decode::<Claims>(
        token,
        &DecodingKey::from_secret(std::env::var("JWT_SECRET").unwrap().as_bytes()),
        &Validation::default(),
    ) {
        Ok(data) => data,
        Err(_) => return HttpResponse::Unauthorized().body("Invalid token"),
    };

    // Parse UUID from `sub`
    let user_id = match Uuid::parse_str(&token_data.claims.sub) {
        Ok(id) => id,
        Err(_) => return HttpResponse::BadRequest().body("Invalid user ID"),
    };

    // Find existing user
    let existing = match Entity::find_by_id(user_id).one(&**db).await {
        Ok(Some(u)) => u,
        Ok(None) => return HttpResponse::NotFound().body("User not found"),
        Err(_) => return HttpResponse::InternalServerError().body("Database error"),
    };

    // Hash password
    let hashed_password = match hash(&user.password, DEFAULT_COST) {
        Ok(hp) => hp,
        Err(_) => return HttpResponse::InternalServerError().body("Password hashing failed"),
    };

    // Update fields
    let mut updated_user: ActiveModel = existing.into_active_model();
    updated_user.name = Set(user.name.clone());
    updated_user.lastname = Set(user.lastname.clone());
    updated_user.email = Set(user.email.clone());
    updated_user.password = Set(hashed_password);

    // Save changes
    if let Err(_) = updated_user.update(&**db).await {
        return HttpResponse::InternalServerError().body("Failed to update user");
    }
    HttpResponse::Ok().json(serde_json::json!({
        "message": "User updated successfully"
    }))
}

#[delete("/account")]
pub async fn delete(db: web::Data<DbConn>, req: HttpRequest) -> impl Responder {
    let auth_header = match req
        .headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
    {
        Some(h) => h,
        None => return HttpResponse::Unauthorized().body("Missing Authorization header"),
    };

    let token = match auth_header.strip_prefix("Bearer ") {
        Some(t) => t,
        None => return HttpResponse::Unauthorized().body("Missing Bearer prefix"),
    };

    let jwt_secret = std::env::var("JWT_SECRET").unwrap_or_else(|_| "secret".into());

    let token_data = match decode::<Claims>(
        token,
        &DecodingKey::from_secret(jwt_secret.as_bytes()),
        &Validation::default(),
    ) {
        Ok(data) => data,
        Err(_) => return HttpResponse::Unauthorized().body("Invalid token"),
    };

    let user_uuid = match Uuid::parse_str(&token_data.claims.sub) {
        Ok(uuid) => uuid,
        Err(_) => return HttpResponse::BadRequest().body("Invalid user ID in token"),
    };

    match Entity::delete_by_id(user_uuid).exec(&**db).await {
        Ok(res) if res.rows_affected > 0 => HttpResponse::Ok().json(serde_json::json!({
            "message": "User deleted successfully",
            "user_id": user_uuid
        })),
        Ok(_) => HttpResponse::NotFound().body("User not found"),
        Err(_) => HttpResponse::InternalServerError().body("Database error"),
    }
}
