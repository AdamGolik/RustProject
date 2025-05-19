use actix_web::{delete, get, post, put, web, HttpRequest, HttpResponse, Responder};
use jsonwebtoken::{decode, DecodingKey, Validation};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, Condition, DbConn, EntityTrait, PaginatorTrait, QueryFilter,
    QueryOrder, Set,
};
use serde::Deserialize;
use uuid::Uuid;

use crate::{
    entity::{client, client::ActiveModel as ClientModel},
    middleware::jwt::Claims,
};

// Helper function to extract user UUID from JWT token
async fn extract_user_uuid(req: &HttpRequest) -> Result<Uuid, HttpResponse> {
    // 1. Authorization header
    let auth_header = req
        .headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok());
    let Some(auth_header) = auth_header else {
        return Err(HttpResponse::Unauthorized().body("Missing Authorization header"));
    };
    let Some(token) = auth_header.strip_prefix("Bearer ") else {
        return Err(HttpResponse::Unauthorized().body("Missing Bearer prefix"));
    };

    // 2. Decode JWT
    let jwt_secret = std::env::var("JWT_SECRET").unwrap_or_else(|_| "secret".into());
    let token_data = match decode::<Claims>(
        token,
        &DecodingKey::from_secret(jwt_secret.as_bytes()),
        &Validation::default(),
    ) {
        Ok(data) => data,
        Err(_) => return Err(HttpResponse::Unauthorized().body("Invalid token")),
    };

    // 3. Parse UUID
    match Uuid::parse_str(&token_data.claims.sub) {
        Ok(id) => Ok(id),
        Err(_) => Err(HttpResponse::BadRequest().body("Invalid user ID in token")),
    }
}

// CREATE - Add new client
#[post("/add")]
pub async fn add_client(
    db: web::Data<DbConn>,
    req: HttpRequest,
    clt: web::Json<client::Controller>,
) -> impl Responder {
    let user_uuid = match extract_user_uuid(&req).await {
        Ok(uuid) => uuid,
        Err(response) => return response,
    };

    // Create new client
    let new_client = ClientModel {
        uuid: Set(Uuid::new_v4()),
        name: Set(clt.name.clone()),
        lastname: Set(clt.lastname.clone()),
        telephone: Set(clt.telephone.clone()),
        title: Set(clt.title.clone()),
        description: Set(clt.description.clone()),
        time_from: Set(clt.time_from),
        time_to: Set(clt.time_to),
        datetime: Set(clt.datetime),
        added_description: Set(clt.added_description.clone().unwrap_or_default()),
        user_uuid: Set(user_uuid),
    };

    // Save client
    match new_client.insert(&**db).await {
        Ok(saved) => HttpResponse::Created().json(serde_json::json!({
            "message": "Client added successfully",
            "client": saved
        })),
        Err(e) => {
            eprintln!("Insert error: {:?}", e);
            HttpResponse::InternalServerError().body("Failed to add client")
        }
    }
}

// READ - Get single client by UUID
#[get("/{client_uuid}")]
pub async fn get_client(
    db: web::Data<DbConn>,
    req: HttpRequest,
    path: web::Path<Uuid>,
) -> impl Responder {
    let user_uuid = match extract_user_uuid(&req).await {
        Ok(uuid) => uuid,
        Err(response) => return response,
    };

    let client_uuid = path.into_inner();

    match client::Entity::find_by_id(client_uuid)
        .filter(client::Column::UserUuid.eq(user_uuid))
        .one(&**db)
        .await
    {
        Ok(Some(client)) => HttpResponse::Ok().json(client),
        Ok(None) => HttpResponse::NotFound().body("Client not found"),
        Err(e) => {
            eprintln!("Database error: {:?}", e);
            HttpResponse::InternalServerError().body("Failed to fetch client")
        }
    }
}

// READ - Get all clients for the user with pagination
#[derive(Deserialize)]
pub struct GetClientsQuery {
    page: Option<u64>,
    per_page: Option<u64>,
    search: Option<String>,
}

#[get("/")]
pub async fn get_clients(
    db: web::Data<DbConn>,
    req: HttpRequest,
    query: web::Query<GetClientsQuery>,
) -> impl Responder {
    let user_uuid = match extract_user_uuid(&req).await {
        Ok(uuid) => uuid,
        Err(response) => return response,
    };

    let page = query.page.unwrap_or(1);
    let per_page = query.per_page.unwrap_or(10).min(100); // Limit to 100 per page

    let mut select = client::Entity::find()
        .filter(client::Column::UserUuid.eq(user_uuid))
        .order_by_desc(client::Column::Datetime);

    // Add search filter if provided
    if let Some(search) = &query.search {
        let search_condition = Condition::any()
            .add(client::Column::Name.contains(search))
            .add(client::Column::Lastname.contains(search))
            .add(client::Column::Title.contains(search))
            .add(client::Column::Telephone.contains(search));
        select = select.filter(search_condition);
    }

    match select
        .clone()
        .paginate(&**db, per_page)
        .fetch_page(page - 1)
        .await
    {
        Ok(clients) => {
            // Get total count for pagination info
            let total = select.count(&**db).await.unwrap_or(0);
            let total_pages = (total + per_page - 1) / per_page;

            HttpResponse::Ok().json(serde_json::json!({
                "clients": clients,
                "pagination": {
                    "page": page,
                    "per_page": per_page,
                    "total": total,
                    "total_pages": total_pages
                }
            }))
        }
        Err(e) => {
            eprintln!("Database error: {:?}", e);
            HttpResponse::InternalServerError().body("Failed to fetch clients")
        }
    }
}

// UPDATE - Update existing client
#[derive(Deserialize)]
pub struct UpdateClient {
    pub name: Option<String>,
    pub lastname: Option<String>,
    pub telephone: Option<String>,
    pub title: Option<String>,
    pub description: Option<String>,
    pub time_from: Option<chrono::NaiveDateTime>,
    pub time_to: Option<chrono::NaiveDateTime>,
    pub datetime: Option<chrono::NaiveDateTime>,
    pub added_description: Option<serde_json::Value>,
}

#[put("/{client_uuid}")]
pub async fn update_client(
    db: web::Data<DbConn>,
    req: HttpRequest,
    path: web::Path<Uuid>,
    update_data: web::Json<UpdateClient>,
) -> impl Responder {
    let user_uuid = match extract_user_uuid(&req).await {
        Ok(uuid) => uuid,
        Err(response) => return response,
    };

    let client_uuid = path.into_inner();

    // First, check if client exists and belongs to the user
    let existing_client = match client::Entity::find_by_id(client_uuid)
        .filter(client::Column::UserUuid.eq(user_uuid))
        .one(&**db)
        .await
    {
        Ok(Some(client)) => client,
        Ok(None) => return HttpResponse::NotFound().body("Client not found"),
        Err(e) => {
            eprintln!("Database error: {:?}", e);
            return HttpResponse::InternalServerError().body("Failed to fetch client");
        }
    };

    // Convert to ActiveModel for updating
    let mut client_active: client::ActiveModel = existing_client.into();

    // Update fields if provided
    if let Some(name) = &update_data.name {
        client_active.name = Set(name.clone());
    }
    if let Some(lastname) = &update_data.lastname {
        client_active.lastname = Set(lastname.clone());
    }
    if let Some(telephone) = &update_data.telephone {
        client_active.telephone = Set(telephone.clone());
    }
    if let Some(title) = &update_data.title {
        client_active.title = Set(title.clone());
    }
    if let Some(description) = &update_data.description {
        client_active.description = Set(description.clone());
    }
    if let Some(time_from) = update_data.time_from {
        client_active.time_from = Set(time_from);
    }
    if let Some(time_to) = update_data.time_to {
        client_active.time_to = Set(time_to);
    }
    if let Some(datetime) = update_data.datetime {
        client_active.datetime = Set(datetime);
    }
    if let Some(added_description) = &update_data.added_description {
        client_active.added_description = Set(added_description.clone());
    }

    // Save the updated client
    match client_active.update(&**db).await {
        Ok(updated_client) => HttpResponse::Ok().json(serde_json::json!({
            "message": "Client updated successfully",
            "client": updated_client
        })),
        Err(e) => {
            eprintln!("Update error: {:?}", e);
            HttpResponse::InternalServerError().body("Failed to update client")
        }
    }
}

// DELETE - Delete client
#[delete("/{client_uuid}")]
pub async fn delete_client(
    db: web::Data<DbConn>,
    req: HttpRequest,
    path: web::Path<Uuid>,
) -> impl Responder {
    let user_uuid = match extract_user_uuid(&req).await {
        Ok(uuid) => uuid,
        Err(response) => return response,
    };

    let client_uuid = path.into_inner();

    // First, check if client exists and belongs to the user
    let existing_client = match client::Entity::find_by_id(client_uuid)
        .filter(client::Column::UserUuid.eq(user_uuid))
        .one(&**db)
        .await
    {
        Ok(Some(client)) => client,
        Ok(None) => return HttpResponse::NotFound().body("Client not found"),
        Err(e) => {
            eprintln!("Database error: {:?}", e);
            return HttpResponse::InternalServerError().body("Failed to fetch client");
        }
    };

    // Delete the client
    let client_active: client::ActiveModel = existing_client.into();
    match client_active.delete(&**db).await {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({
            "message": "Client deleted successfully"
        })),
        Err(e) => {
            eprintln!("Delete error: {:?}", e);
            HttpResponse::InternalServerError().body("Failed to delete client")
        }
    }
}

// Additional helper endpoint - Get clients by date range
#[derive(Deserialize)]
pub struct DateRangeQuery {
    from: chrono::NaiveDateTime,
    to: chrono::NaiveDateTime,
}

#[get("/by-date-range")]
pub async fn get_clients_by_date_range(
    db: web::Data<DbConn>,
    req: HttpRequest,
    query: web::Query<DateRangeQuery>,
) -> impl Responder {
    let user_uuid = match extract_user_uuid(&req).await {
        Ok(uuid) => uuid,
        Err(response) => return response,
    };

    match client::Entity::find()
        .filter(client::Column::UserUuid.eq(user_uuid))
        .filter(client::Column::Datetime.between(query.from, query.to))
        .order_by_asc(client::Column::Datetime)
        .all(&**db)
        .await
    {
        Ok(clients) => HttpResponse::Ok().json(clients),
        Err(e) => {
            eprintln!("Database error: {:?}", e);
            HttpResponse::InternalServerError().body("Failed to fetch clients")
        }
    }
}
