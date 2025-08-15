package model

type Config struct {
	BaseURL      string
	BudgetID     string
	ActualAPIKey string
}

type Account struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Offbudget bool   `json:"offbudget"`
	Closed    bool   `json:"closed"`
}

type Category struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type Payee struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	CategoryID     string `json:"category"`
	TransferAcctID string `json:"transfer_acct"`
}

type Transaction struct {
	Account   string `json:"account"`
	Category  string `json:"category,omitempty"`
	Amount    int    `json:"amount"`
	PayeeID   string `json:"payee,omitempty"`
	PayeeName string `json:"imported_payee,omitempty"`
	Date      string `json:"date"`
	Cleared   bool   `json:"cleared"`
	Notes     string `json:"notes,omitempty"`
	IsParent  bool   `json:"is_parent,omitempty"`
	IsChild   bool   `json:"is_child,omitempty"`
	ParentID  string `json:"parent_id,omitempty"`
}

type CreateTransactionRequest struct {
	LearnCategories bool        `json:"learnCategories"`
	RunTransfers    bool        `json:"runTransfers"`
	Transaction     Transaction `json:"transaction"`
	Date            string      `json:"date"`
}

type CreateRuleRequest struct {
	Rule Rule `json:"rule"`
}

type UpdateAccountRequest struct {
	Account struct {
		Name string `json:"name"`
	} `json:"account"`
}

type Rule struct {
	ID           string      `json:"id,omitempty"`
	Stage        string      `json:"stage"`
	ConditionsOp string      `json:"conditionsOp,omitempty"`
	Conditions   []Condition `json:"conditions,omitempty"`
	Actions      []Action    `json:"actions,omitempty"`
}

type Condition struct {
	Op    string      `json:"op"`
	Field string      `json:"field"`
	Value interface{} `json:"value"`
	Type  string      `json:"type,omitempty"`
}

type Action struct {
	Op      string                 `json:"op"`
	Field   string                 `json:"field"`
	Value   interface{}            `json:"value"`
	Type    string                 `json:"type,omitempty"`
	Options map[string]interface{} `json:"options,omitempty"`
}

// Response structures

type TransactionsResponse struct {
	Data []Transaction `json:"data"`
}

type AccountsResponse struct {
	Data []Account `json:"data"`
}

type BalanceResponse struct {
	Data int `json:"data"` // Expect integer cents/smallest unit
}

type PayeesResponse struct {
	Data []Payee `json:"data"`
}

type CategoriesResponse struct {
	Data []Category `json:"data"`
}

type RulesResponse struct {
	Data []Rule `json:"data"`
}
