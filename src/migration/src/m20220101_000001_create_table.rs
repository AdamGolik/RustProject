use sea_orm_migration::{prelude::*, schema::*};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Replace the sample below with your own migration scripts
        //todo!();

        manager
            .create_table(
                Table::create()
                    .table(User::Table)
                    .if_not_exists()
                    .col(pk_uuid(User::Uuid))
                    .col(string(User::Name))
                    .col(string(User::Lastname))
                    .col(string(User::Email).not_null().unique_key())
                    .col(string(User::Password).not_null())
                    .to_owned(),
            )
            .await?;
        // Tworzenie tabeli Client z relacją many-to-one do User
        manager
            .create_table(
                Table::create()
                    .table(Client::Table)
                    .if_not_exists()
                    .col(pk_uuid(Client::Uuid))
                    .col(string(Client::Name))
                    .col(string(Client::Lastname))
                    .col(string(Client::Telephone))
                    .col(string(Client::Title))
                    .col(text(Client::Description))
                    .col(date_time(Client::TimeFrom))
                    .col(date_time(Client::TimeTo))
                    .col(date_time(Client::Datetime))
                    .col(json(Client::AddedDescription)) // assuming array[string] -> use JSON
                    .col(uuid(Client::UserUuid)) // foreign key
                    .foreign_key(
                        ForeignKey::create()
                            .from(Client::Table, Client::UserUuid)
                            .to(User::Table, User::Uuid)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Replace the sample below with your own migration scripts
        // todo!();
        manager
            .drop_table(Table::drop().table(User::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(Client::Table).to_owned())
            .await
    }
}

#[derive(DeriveIden)]
enum User {
    Table,
    Uuid,
    Name,
    Lastname,
    Email,
    Password,
}

#[derive(DeriveIden)]
enum Client {
    Table,
    Uuid,
    Name,
    Lastname,
    Telephone,
    Title,
    Description,
    TimeFrom,
    TimeTo,
    Datetime,
    AddedDescription,
    UserUuid,
}

