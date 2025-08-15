package model

// Config holds the necessary configuration for the Actual Budget API client.
type Config struct {
	BaseURL      string // BaseURL is the URL of the Actual API server.
	BudgetID     string // BudgetID is the ID of the budget to interact with.
	ActualAPIKey string // ActualAPIKey is the API key for authentication.
}

// Account represents a financial account in Actual.
type Account struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Offbudget bool   `json:"offbudget"`
	Closed    bool   `json:"closed"`
}

// Category represents a spending category in Actual.
type Category struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Payee represents a payee or payer in Actual.
type Payee struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	CategoryID     string `json:"category"`
	TransferAcctID string `json:"transfer_acct"`
}

// Transaction represents a single financial transaction in Actual.
type Transaction struct {
	Account   string `json:"account"`
	Category  string `json:"category,omitempty"`
	Amount    int    `json:"amount"` // Amount is in integer cents/smallest unit.
	PayeeID   string `json:"payee,omitempty"`
	PayeeName string `json:"imported_payee,omitempty"`
	Date      string `json:"date"` // Date is in "YYYY-MM-DD" format.
	Cleared   bool   `json:"cleared"`
	Notes     string `json:"notes,omitempty"`
	IsParent  bool   `json:"is_parent,omitempty"`
	IsChild   bool   `json:"is_child,omitempty"`
	ParentID  string `json:"parent_id,omitempty"`
}

// CreateTransactionRequest is the request body for creating a new transaction.
type CreateTransactionRequest struct {
	LearnCategories bool        `json:"learnCategories"`
	RunTransfers    bool        `json:"runTransfers"`
	Transaction     Transaction `json:"transaction"`
	Date            string      `json:"date"`
}

// CreateRuleRequest is the request body for creating a new rule.
type CreateRuleRequest struct {
	Rule Rule `json:"rule"`
}

// UpdateAccountRequest is the request body for updating an account.
type UpdateAccountRequest struct {
	Account struct {
		Name string `json:"name"`
	} `json:"account"`
}

// Rule represents a rule for automatically processing transactions.
type Rule struct {
	ID           string      `json:"id,omitempty"`
	Stage        string      `json:"stage"`
	ConditionsOp string      `json:"conditionsOp,omitempty"`
	Conditions   []Condition `json:"conditions,omitempty"`
	Actions      []Action    `json:"actions,omitempty"`
}

// Condition is a part of a Rule that specifies a condition to be met.
type Condition struct {
	Op    string      `json:"op"`
	Field string      `json:"field"`
	Value interface{} `json:"value"`
	Type  string      `json:"type,omitempty"`
}

// Action is a part of a Rule that specifies an action to be taken.
type Action struct {
	Op      string                 `json:"op"`
	Field   string                 `json:"field"`
	Value   interface{}            `json:"value"`
	Type    string                 `json:"type,omitempty"`
	Options map[string]interface{} `json:"options,omitempty"`
}

// Response structures

// TransactionsResponse is the API response for a list of transactions.
type TransactionsResponse struct {
	Data []Transaction `json:"data"`
}

// AccountsResponse is the API response for a list of accounts.
type AccountsResponse struct {
	Data []Account `json:"data"`
}

// BalanceResponse is the API response for an account balance.
type BalanceResponse struct {
	Data int `json:"data"` // Expect integer cents/smallest unit
}

// PayeesResponse is the API response for a list of payees.
type PayeesResponse struct {
	Data []Payee `json:"data"`
}

// CategoriesResponse is the API response for a list of categories.
type CategoriesResponse struct {
	Data []Category `json:"data"`
}

// RulesResponse is the API response for a list of rules.
type RulesResponse struct {
	Data []Rule `json:"data"`
}
