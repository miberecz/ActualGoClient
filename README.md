# Actual Budget API Client

This package provides a client for interacting with the Actual Budget API.

## Components

*   **`client.go`**: Implements the `Client` interface, handling HTTP requests, responses, and caching (specifically for payees). It requires configuration (`model.Config`) and a logger (`*slog.Logger`) for initialization.
*   **`model/model.go`**: Defines the Go structs that map to the JSON request and response bodies of the Actual Budget API endpoints used by this application (Accounts, Transactions, Payees, Categories, Rules, Balance). It also includes the main `Config` struct used by the client.

## Functionality

The client provides methods to:
*   Fetch budget data (Accounts, Payees, Categories, Rules, Transactions, Account Balance).
*   Create and update Transactions.
*   Create and update Rules.
*   Manage a cache for Payee IDs to minimize API calls.