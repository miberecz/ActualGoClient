# Actual Budget API Go Client

A Go client for interacting with the [Actual HTTP API](https://github.com/jhonderson/actual-http-api). This package simplifies the process of fetching and manipulating your budget data programmatically.

## Features

*   Fetch accounts, categories, payees, rules, and transactions.
*   Get the current balance for any account.
*   Create and update transactions.
*   Create and update rules.
*   Delete transactions.
*   Efficiently caches payee data to reduce API calls.
*   Requires a `slog.Logger` for structured logging.

## Installation

To add the client to your project, run:

```sh
go get github.com/miberecz/ActualGoClient
```

## Usage

Here is a basic example of how to initialize the client and fetch your accounts.

### Initializing the Client

First, you need to configure the client with your Actual server details and API key.

```go
package main

import (
    "log/slog"
    "os"

    "github.com/miberecz/ActualGoClient"
    "github.com/miberecz/ActualGoClient/model"
)

func main() {
    // It's recommended to use a structured logger.
    logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

    // Configure the client. Use environment variables for sensitive data.
    config := &model.Config{
        BaseURL:      "https://your-actual-instance.com/", // Replace with your server URL
        BudgetID:     os.Getenv("ACTUAL_BUDGET_ID"),
        ActualAPIKey: os.Getenv("ACTUAL_API_KEY"),
    }

    client := ActualGoClient.NewClient(config, logger)

    // Now you can use the client to interact with the API.
    accounts, err := client.GetAccounts()
    if err != nil {
        logger.Error("Failed to get accounts", "error", err)
        return
    }

    for _, acc := range accounts {
        logger.Info("Found account", "id", acc.ID, "name", acc.Name)
    }
}
```

### Creating a Transaction

This example shows how to create a new transaction. The amount should be provided in integer cents (or the smallest currency unit).

```go
// ... (inside main or another function)

    transaction := model.Transaction{
        Account:   "account_id_to_add_transaction_to", // Target account ID
        Amount:    -1250, // -12.50 in the main currency unit
        PayeeName: "Coffee Shop",
        Date:      "2024-05-21",
        Notes:     "Morning coffee",
    }

    req := model.CreateTransactionRequest{
        Transaction: transaction,
    }

    err := client.CreateTransaction(transaction.Account, req)
    if err != nil {
        logger.Error("Failed to create transaction", "error", err)
    } else {
        logger.Info("Successfully created transaction")
    }
```

## API Documentation

For a complete list of available methods, see the `Client` interface in [`client.go`](client.go) and the data structures in [`model/model.go`](model/model.go). The public functions and types are documented with GoDoc comments.

## Components

*   **`client.go`**: Implements the `Client` interface, handling HTTP requests, responses, and caching (specifically for payees). It requires configuration (`model.Config`) and a logger (`*slog.Logger`) for initialization.
*   **`model/model.go`**: Defines the Go structs that map to the JSON request and response bodies of the Actual Budget API.