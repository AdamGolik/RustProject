# SaraSyste - System Zarządzania Klientami

## Opis Systemu
SaraSyste to backend system zarządzania klientami napisany w Rust z wykorzystaniem frameworka Actix Web. System zapewnia pełną funkcjonalność zarządzania użytkownikami i klientami, z wbudowanym systemem autoryzacji JWT.

## Wymagania Systemowe
- Rust (najnowsza stabilna wersja)
- PostgreSQL
- Node.js (dla frontendu)

## Konfiguracja Środowiska

1. Utwórz plik `.env` w głównym katalogu projektu z następującymi zmiennymi:
```env
DATABASE_URL=postgres://username:password@localhost:5432/database_name
JWT_SECRET=twoj_tajny_klucz_jwt
```

2. Zainstaluj zależności:
```bash
cargo build
```

3. Uruchom migracje bazy danych:
```bash
cargo run
```

## Struktura API

### Autoryzacja

#### Rejestracja Użytkownika
- **Endpoint**: `POST /register`
- **Body**:
```json
{
    "email": "user@example.com",
    "password": "haslo123",
    "name": "Jan Kowalski"
}
```

#### Logowanie
- **Endpoint**: `POST /login`
- **Body**:
```json
{
    "email": "user@example.com",
    "password": "haslo123"
}
```
- **Response**: Zwraca token JWT do autoryzacji

### Endpointy Użytkownika (Wymagają JWT)

#### Pobierz Ustawienia
- **Endpoint**: `GET /user/settings`
- **Headers**: `Authorization: Bearer <token>`

#### Aktualizuj Profil
- **Endpoint**: `PUT /user/update`
- **Headers**: `Authorization: Bearer <token>`
- **Body**:
```json
{
    "name": "Nowe Imię",
    "email": "nowy@email.com"
}
```

#### Usuń Konto
- **Endpoint**: `DELETE /user/delete`
- **Headers**: `Authorization: Bearer <token>`

### Endpointy Klientów (Wymagają JWT)

#### Dodaj Klienta
- **Endpoint**: `POST /clients/add`
- **Headers**: `Authorization: Bearer <token>`
- **Body**:
```json
{
    "name": "Imię",
    "lastname": "Nazwisko",
    "telephone": "123456789",
    "title": "Tytuł",
    "description": "Opis",
    "time_from": "2024-03-20T10:00:00",
    "time_to": "2024-03-20T11:00:00",
    "datetime": "2024-03-20T09:00:00",
    "added_description": {
        "contact_preference": "telephone",
        "notes": "VIP client",
        "priority": "high",
        "tags": [
            "very valid",
            "follow-up"
        ]
    }
}
```
- **Response**: 
```json
{
    "client": {
        "added_description": {
            "contact_preference": "telephone",
            "notes": "VIP client",
            "priority": "high",
            "tags": [
                "very valid",
                "follow-up"
            ]
        },
        "datetime": "2024-05-10T22:23:00",
        "description": "Initial consultation",
        "lastname": "Nazwisko",
        "name": "Imię",
        "telephone": "+1234567890",
        "time_from": "2024-05-04T20:46:00",
        "time_to": "2024-06-09T00:00:00",
        "title": "Tytuł",
        "user_uuid": "d2c898fd-bf2a-4663-b556-e0d5cdca26b6",
        "uuid": "7f2e19b0-d613-4aaa-95f3-8b4fb903c817"
    },
    "message": "Client added successfully"
}
```

#### Pobierz Klienta
- **Endpoint**: `GET /clients/{client_uuid}`
- **Headers**: `Authorization: Bearer <token>`
- **Response**: 
```json
{
    "uuid": "client-uuid",
    "name": "Imię",
    "lastname": "Nazwisko",
    "telephone": "123456789",
    "title": "Tytuł",
    "description": "Opis",
    "time_from": "2024-03-20T10:00:00",
    "time_to": "2024-03-20T11:00:00",
    "datetime": "2024-03-20T09:00:00",
    "added_description": {
        "contact_preference": "telephone",
        "notes": "VIP client",
        "priority": "high",
        "tags": [
            "very valid",
            "follow-up"
        ]
    },
    "user_uuid": "user-uuid"
}
```

#### Pobierz Wszystkich Klientów
- **Endpoint**: `GET /clients`
- **Headers**: `Authorization: Bearer <token>`
- **Query Parameters**:
  - `page` (opcjonalny, domyślnie 1): Numer strony
  - `per_page` (opcjonalny, domyślnie 10, max 100): Liczba klientów na stronę
  - `search` (opcjonalny): Wyszukiwanie po imieniu, nazwisku, tytule lub telefonie
- **Response**:
```json
{
    "clients": [
        {
            "uuid": "client-uuid",
            "name": "Imię",
            "lastname": "Nazwisko",
            "telephone": "123456789",
            "title": "Tytuł",
            "description": "Opis",
            "time_from": "2024-03-20T10:00:00",
            "time_to": "2024-03-20T11:00:00",
            "datetime": "2024-03-20T09:00:00",
            "added_description": {
                "contact_preference": "telephone",
                "notes": "VIP client",
                "priority": "high",
                "tags": [
                    "very valid",
                    "follow-up"
                ]
            },
            "user_uuid": "user-uuid"
        }
    ],
    "pagination": {
        "page": 1,
        "per_page": 10,
        "total": 100,
        "total_pages": 10
    }
}
```

#### Aktualizuj Klienta
- **Endpoint**: `PUT /clients/{client_uuid}`
- **Headers**: `Authorization: Bearer <token>`
- **Body** (wszystkie pola są opcjonalne):
```json
{
    "name": "Nowe Imię",
    "lastname": "Nowe Nazwisko",
    "telephone": "987654321",
    "title": "Nowy Tytuł",
    "description": "Nowy Opis",
    "time_from": "2024-03-21T10:00:00",
    "time_to": "2024-03-21T11:00:00",
    "datetime": "2024-03-21T09:00:00",
    "added_description": {
        "contact_preference": "email",
        "notes": "Updated notes",
        "priority": "medium",
        "tags": [
            "updated",
            "new-tag"
        ]
    }
}
```
- **Response**: Zaktualizowany obiekt klienta

#### Usuń Klienta
- **Endpoint**: `DELETE /clients/{client_uuid}`
- **Headers**: `Authorization: Bearer <token>`
- **Response**: Status 204 No Content w przypadku sukcesu

#### Pobierz Klientów z Zakresu Dat
- **Endpoint**: `GET /clients/date-range`
- **Headers**: `Authorization: Bearer <token>`
- **Query Parameters**:
  - `from`: Data początkowa w formacie ISO 8601 (np. "2024-03-20T00:00:00")
  - `to`: Data końcowa w formacie ISO 8601 (np. "2024-03-21T23:59:59")
- **Response**: Lista klientów z danego zakresu dat

## Struktura Projektu

```
src/
├── controller/         # Kontrolery obsługujące endpointy
│   ├── client.rs      # Logika zarządzania klientami
│   └── user.rs        # Logika zarządzania użytkownikami
├── entity/            # Modele danych
│   ├── client.rs      # Model klienta
│   └── user.rs        # Model użytkownika
├── middleware/        # Middleware'y
│   └── jwt.rs         # Obsługa autoryzacji JWT
└── migration/         # Migracje bazy danych
```

## Bezpieczeństwo

- Wszystkie endpointy (oprócz rejestracji i logowania) wymagają tokenu JWT
- Hasła są hashowane przed zapisem w bazie danych
- CORS jest skonfigurowany dla bezpiecznej komunikacji z frontendem
- Wszystkie wrażliwe dane są przechowywane w zmiennych środowiskowych

## Integracja z Frontendem

1. Podstawowy URL API: `http://localhost:8080`
2. Wszystkie żądania do chronionych endpointów muszą zawierać nagłówek:
```
Authorization: Bearer <token_jwt>
```

3. Przykład użycia w JavaScript/TypeScript:
```typescript
const fetchClients = async (token: string) => {
    const response = await fetch('http://localhost:8080/clients', {
        headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json'
        }
    });
    return await response.json();
};
```

## Obsługa Błędów

System zwraca standardowe kody HTTP:
- 200: Sukces
- 400: Błędne żądanie
- 401: Brak autoryzacji
- 403: Brak uprawnień
- 404: Nie znaleziono
- 500: Błąd serwera

Każda odpowiedź błędu zawiera szczegółowy komunikat w formacie JSON.

## Rozwój

1. Klonuj repozytorium
2. Skonfiguruj środowisko zgodnie z instrukcjami powyżej
3. Uruchom serwer deweloperski:
```bash
cargo run
```

## Licencja

[Określ licencję projektu]