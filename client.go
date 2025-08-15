package ActualGoClient

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"

	"github.com/miberecz/ActualGoClient/model"
)

// Client defines the interface for interacting with the Actual Budget API.
// It provides methods for fetching and manipulating budget data such as accounts,
// transactions, categories, payees, and rules.
type Client interface {
	// GetAccounts retrieves all accounts for the configured budget.
	GetAccounts() ([]model.Account, error)
	// GetBalance retrieves the current balance for a specific account.
	// The balance is returned as a float64, representing the value in the major currency unit (e.g., dollars).
	GetBalance(accountID string) (float64, error)
	// GetCategories retrieves all categories for the configured budget.
	GetCategories() ([]model.Category, error)
	// GetPayees retrieves all payees for the configured budget.
	// This method utilizes an internal cache to reduce API calls.
	GetPayees() ([]model.Payee, error)
	// GetPayeeIDByName retrieves the ID of a payee by their name.
	// It uses a cache for efficiency. If the cache is not populated, it will be fetched first.
	GetPayeeIDByName(name string) (string, error)
	// GetRules retrieves all rules for the configured budget.
	// An optional stageFilter can be provided to filter rules by their stage (e.g., "pre").
	GetRules(stageFilter string) ([]model.Rule, error)
	// CreateTransaction creates a new transaction in a specific account.
	CreateTransaction(accountID string, req model.CreateTransactionRequest) error
	// CreateRule creates a new rule for the budget.
	CreateRule(rule model.Rule) error
	// UpdateRule updates an existing rule identified by its ID.
	UpdateRule(ruleID string, rule model.Rule) error
	// UpdateAccount updates the name of an existing account.
	UpdateAccount(accountID string, newName string) error
	// GetTransactions retrieves transactions for a specific account within a given date range.
	// sinceDate and untilDate should be in "YYYY-MM-DD" format. They are optional.
	GetTransactions(accountID, sinceDate, untilDate string) ([]model.Transaction, error)
	// DeleteTransaction deletes a transaction by its ID.
	DeleteTransaction(transactionID string) error
}

// httpClient implements the Client interface.
type httpClient struct {
	config        *model.Config
	httpClient    *http.Client
	payeeCache    map[string]string
	cacheMutex    sync.RWMutex
	payeesFetched bool
	logger        *slog.Logger
}

// NewClient creates a new client for interacting with the Actual Budget API.
// It requires a configuration object with API details and a slog.Logger for logging.
func NewClient(config *model.Config, logger *slog.Logger) Client {
	return &httpClient{
		config:     config,
		httpClient: &http.Client{},
		payeeCache: make(map[string]string),
		logger:     logger,
	}
}

// ensurePayeeCache populates the payee cache if it hasn't been fetched yet.
// It is safe for concurrent use.
func (c *httpClient) ensurePayeeCache() error {
	c.cacheMutex.RLock()
	fetched := c.payeesFetched
	c.cacheMutex.RUnlock()

	if fetched {
		c.logger.Debug("Payee cache already populated", "event", "CacheHit")
		return nil
	}

	c.cacheMutex.Lock()
	defer c.cacheMutex.Unlock()

	// Double-check after acquiring write lock
	if c.payeesFetched {
		c.logger.Debug("Payee cache populated by another goroutine", "event", "CacheHitRace")
		return nil
	}

	c.logger.Info("Fetching payees to populate cache", "event", "FetchPayeesStart", "reason", "Cache empty")
	payees, err := c.getPayeesInternal()
	if err != nil {
		// Error already logged in getPayeesInternal/doRequest
		c.logger.Error("Failed to fetch payees for cache", "event", "FetchPayeesError", "error", err)
		return fmt.Errorf("failed to fetch payees for cache: %w", err)
	}

	for _, payee := range payees {
		c.payeeCache[payee.Name] = payee.ID
	}
	c.payeesFetched = true
	c.logger.Info("Payee cache populated successfully", "event", "FetchPayeesSuccess", "payee_count", len(payees))
	return nil
}

// getPayeesInternal performs the actual API call to fetch payees without caching logic.
func (c *httpClient) getPayeesInternal() ([]model.Payee, error) {
	url := fmt.Sprintf("%sbudgets/%s/payees", c.config.BaseURL, c.config.BudgetID)
	resp, err := c.doRequest("GET", url, nil)
	if err != nil {
		// doRequest logs details
		return nil, fmt.Errorf("failed getting payees: %w", err)
	}
	defer resp.Body.Close()

	var response model.PayeesResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		c.logger.Error("Failed to decode payees response", "event", "DecodeError", "url", url, "error", err)
		return nil, fmt.Errorf("decoding payees response failed: %w", err)
	}
	c.logger.Debug("Successfully fetched and decoded payees", "event", "FetchPayeesInternalSuccess", "count", len(response.Data))
	return response.Data, nil
}

// GetPayees retrieves all payees for the configured budget.
// This method utilizes an internal cache to reduce API calls.
func (c *httpClient) GetPayees() ([]model.Payee, error) {
	if err := c.ensurePayeeCache(); err != nil {
		c.logger.Warn("Payee cache population failed, attempting direct fetch", "event", "GetPayeesWarn", "error", err)
		// Attempt direct fetch if cache failed
		return c.getPayeesInternal()
	}

	// Return data from cache if populated successfully
	c.cacheMutex.RLock()
	defer c.cacheMutex.RUnlock()
	payees := make([]model.Payee, 0, len(c.payeeCache))
	for name, id := range c.payeeCache {
		payees = append(payees, model.Payee{ID: id, Name: name})
	}
	c.logger.Debug("Returning payees from cache", "event", "GetPayeesFromCache", "count", len(payees))
	return payees, nil
}

// GetPayeeIDByName retrieves the ID of a payee by their name.
// It uses a cache for efficiency. If the cache is not populated, it will be fetched first.
func (c *httpClient) GetPayeeIDByName(name string) (string, error) {
	if err := c.ensurePayeeCache(); err != nil {
		// Error already logged by ensurePayeeCache
		return "", err // Return error if cache couldn't be populated
	}

	c.cacheMutex.RLock()
	id, exists := c.payeeCache[name]
	c.cacheMutex.RUnlock()

	if !exists {
		// Log as info/debug level, might not be an error if payee is optional
		c.logger.Debug("Payee not found in cache", "event", "PayeeNotFound", "payee_name", name)
		return "", fmt.Errorf("payee '%s' not found in cache", name)
	}
	c.logger.Debug("Payee found in cache", "event", "PayeeFound", "payee_name", name, "payee_id", id)
	return id, nil
}

// doRequest handles the common logic for making HTTP requests to the Actual API.
func (c *httpClient) doRequest(method, url string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		c.logger.Error("Failed to create HTTP request", "event", "RequestCreationError", "method", method, "url", url, "error", err)
		return nil, fmt.Errorf("request creation failed: %w", err)
	}

	req.Header.Add("Accept", "application/json")
	req.Header.Add("x-api-key", c.config.ActualAPIKey)
	if body != nil {
		req.Header.Add("Content-Type", "application/json")
	}

	c.logger.Debug("Executing API request", "event", "RequestStart", "method", method, "url", url)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		c.logger.Error("API request failed", "event", "RequestError", "method", method, "url", url, "error", err)
		return nil, fmt.Errorf("API request failed: %w", err)
	}

	c.logger.Debug("Received API response", "event", "ResponseReceived", "method", method, "url", url, "status_code", resp.StatusCode)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		errorBody := "Could not read error body"
		if resp.Body != nil {
			bodyBytes, readErr := io.ReadAll(resp.Body)
			// Close body immediately after reading or if read fails
			resp.Body.Close()
			if readErr == nil {
				errorBody = string(bodyBytes)
			} else {
				c.logger.Warn("Failed to read error response body", "event", "ReadErrorBodyFailed", "method", method, "url", url, "status_code", resp.StatusCode, "read_error", readErr)
			}
		} else {
			// Close body even if nil, for consistency (though it's a no-op)
			resp.Body.Close()
		}
		err := fmt.Errorf("unexpected status code: %d - %s", resp.StatusCode, errorBody)
		c.logger.Error("API request returned non-success status", "event", "RequestNonSuccessStatus", "method", method, "url", url, "status_code", resp.StatusCode, "error", err, "response_body", errorBody)
		return nil, err // Return the error
	}

	// Success case, return response (caller is responsible for closing body)
	return resp, nil
}

// GetCategories retrieves all categories for the configured budget.
func (c *httpClient) GetCategories() ([]model.Category, error) {
	url := fmt.Sprintf("%sbudgets/%s/categories", c.config.BaseURL, c.config.BudgetID)
	resp, err := c.doRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed getting categories: %w", err)
	}
	defer resp.Body.Close()

	var response model.CategoriesResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		c.logger.Error("Failed to decode categories response", "event", "DecodeError", "url", url, "error", err)
		return nil, fmt.Errorf("decoding categories response failed: %w", err)
	}
	c.logger.Debug("Successfully fetched categories", "event", "GetCategoriesSuccess", "count", len(response.Data))
	return response.Data, nil
}

// CreateTransaction creates a new transaction in a specific account.
func (c *httpClient) CreateTransaction(accountID string, req model.CreateTransactionRequest) error {
	if accountID == "" {
		err := fmt.Errorf("accountID cannot be empty for CreateTransaction")
		c.logger.Error("Validation failed for CreateTransaction", "event", "ValidationError", "error", err)
		return err
	}
	url := fmt.Sprintf("%sbudgets/%s/accounts/%s/transactions",
		c.config.BaseURL,
		c.config.BudgetID,
		accountID,
	)

	tx := req.Transaction
	// Attempt to resolve Payee ID if name is provided and ID is missing
	if tx.PayeeID == "" && tx.PayeeName != "" {
		c.logger.Debug("Attempting to look up payee ID by name", "event", "PayeeLookupStart", "payee_name", tx.PayeeName, "account_id", accountID)
		payeeID, err := c.GetPayeeIDByName(tx.PayeeName) // Use public method with cache
		if err != nil {
			// Log warning but proceed without ID, Actual might handle it via name
			c.logger.Warn("Payee lookup by name failed, proceeding without Payee ID", "event", "PayeeLookupWarn", "payee_name", tx.PayeeName, "account_id", accountID, "error", err)
			tx.PayeeID = "" // Ensure it's empty
		} else {
			c.logger.Debug("Payee lookup by name succeeded", "event", "PayeeLookupSuccess", "payee_name", tx.PayeeName, "payee_id", payeeID, "account_id", accountID)
			tx.PayeeID = payeeID
		}
	}

	// Use the potentially updated transaction struct
	finalReq := model.CreateTransactionRequest{
		Transaction:     tx,
		LearnCategories: req.LearnCategories,
		RunTransfers:    req.RunTransfers,
		Date:            req.Date, // Ensure date is passed if provided in original req
	}

	body, err := json.Marshal(finalReq)
	if err != nil {
		c.logger.Error("Failed to marshal CreateTransaction request", "event", "MarshalError", "account_id", accountID, "error", err)
		return fmt.Errorf("marshaling CreateTransaction request failed: %w", err)
	}

	resp, err := c.doRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		// Error already logged by doRequest
		return fmt.Errorf("failed creating transaction: %w", err)
	}
	defer resp.Body.Close() // Ensure body is closed on success too

	c.logger.Debug("Successfully created transaction", "event", "CreateTransactionSuccess", "account_id", accountID)
	return nil
}

// GetAccounts retrieves all accounts for the configured budget.
func (c *httpClient) GetAccounts() ([]model.Account, error) {
	url := fmt.Sprintf("%sbudgets/%s/accounts",
		c.config.BaseURL,
		c.config.BudgetID,
	)
	resp, err := c.doRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed getting accounts: %w", err)
	}
	defer resp.Body.Close()

	var accounts model.AccountsResponse
	if err := json.NewDecoder(resp.Body).Decode(&accounts); err != nil {
		c.logger.Error("Failed to decode accounts response", "event", "DecodeError", "url", url, "error", err)
		return nil, fmt.Errorf("decoding accounts response failed: %w", err)
	}
	c.logger.Debug("Successfully fetched accounts", "event", "GetAccountsSuccess", "count", len(accounts.Data))
	return accounts.Data, nil
}

// GetBalance retrieves the current balance for a specific account.
// The balance is returned as a float64, representing the value in the major currency unit (e.g., dollars).
func (c *httpClient) GetBalance(accountID string) (float64, error) {
	if accountID == "" {
		err := fmt.Errorf("accountID cannot be empty for GetBalance")
		c.logger.Error("Validation failed for GetBalance", "event", "ValidationError", "error", err)
		return 0, err
	}
	url := fmt.Sprintf("%sbudgets/%s/accounts/%s/balance",
		c.config.BaseURL,
		c.config.BudgetID,
		accountID,
	)
	resp, err := c.doRequest("GET", url, nil)
	if err != nil {
		return 0, fmt.Errorf("failed getting balance for account %s: %w", accountID, err)
	}
	defer resp.Body.Close()

	var balanceResponse model.BalanceResponse
	if err := json.NewDecoder(resp.Body).Decode(&balanceResponse); err != nil {
		c.logger.Error("Failed to decode balance response", "event", "GetBalanceDecodeError", "account_id", accountID, "url", url, "error", err)
		return 0, fmt.Errorf("decoding balance response failed for account %s: %w", accountID, err)
	}
	balance := float64(balanceResponse.Data) / 100.0
	c.logger.Debug("Successfully fetched balance", "event", "GetBalanceSuccess", "account_id", accountID, "balance", balance)
	return balance, nil
}

// GetRules retrieves all rules for the configured budget.
// An optional stageFilter can be provided to filter rules by their stage (e.g., "pre").
func (c *httpClient) GetRules(stageFilter string) ([]model.Rule, error) {
	url := fmt.Sprintf("%sbudgets/%s/rules", c.config.BaseURL, c.config.BudgetID)
	resp, err := c.doRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed getting rules: %w", err)
	}
	defer resp.Body.Close()

	var response model.RulesResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		c.logger.Error("Failed to decode rules response", "event", "DecodeError", "url", url, "error", err)
		return nil, fmt.Errorf("decoding rules response failed: %w", err)
	}

	// Filter rules by stage if a filter is provided
	if stageFilter == "" {
		c.logger.Debug("Successfully fetched all rules", "event", "GetRulesSuccess", "count", len(response.Data))
		return response.Data, nil
	}

	var filtered []model.Rule
	for _, rule := range response.Data {
		if rule.Stage == stageFilter {
			filtered = append(filtered, rule)
		}
	}
	c.logger.Debug("Successfully fetched and filtered rules", "event", "GetRulesFiltered", "stage", stageFilter, "total_rules", len(response.Data), "filtered_rules", len(filtered))
	return filtered, nil
}

// CreateRule creates a new rule for the budget.
func (c *httpClient) CreateRule(rule model.Rule) error {
	url := fmt.Sprintf("%sbudgets/%s/rules", c.config.BaseURL, c.config.BudgetID)
	reqBody := model.CreateRuleRequest{Rule: rule}
	body, err := json.Marshal(reqBody)
	if err != nil {
		c.logger.Error("Failed to marshal CreateRule request", "event", "MarshalError", "error", err)
		return fmt.Errorf("marshaling CreateRule request failed: %w", err)
	}

	resp, err := c.doRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed creating rule: %w", err)
	}
	defer resp.Body.Close()
	c.logger.Debug("Successfully created rule", "event", "CreateRuleSuccess")
	return nil
}

// UpdateRule updates an existing rule identified by its ID.
func (c *httpClient) UpdateRule(ruleID string, rule model.Rule) error {
	if ruleID == "" {
		err := fmt.Errorf("ruleID cannot be empty for UpdateRule")
		c.logger.Error("Validation failed for UpdateRule", "event", "ValidationError", "error", err)
		return err
	}
	url := fmt.Sprintf("%sbudgets/%s/rules/%s",
		c.config.BaseURL,
		c.config.BudgetID,
		ruleID,
	)
	// Ensure the ID is set in the rule object being sent
	rule.ID = ruleID
	reqBody := model.CreateRuleRequest{Rule: rule}
	body, err := json.Marshal(reqBody)
	if err != nil {
		c.logger.Error("Failed to marshal UpdateRule request", "event", "MarshalError", "rule_id", ruleID, "error", err)
		return fmt.Errorf("marshaling UpdateRule request failed: %w", err)
	}

	resp, err := c.doRequest("PATCH", url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed updating rule %s: %w", ruleID, err)
	}
	defer resp.Body.Close()
	c.logger.Debug("Successfully updated rule", "event", "UpdateRuleSuccess", "rule_id", ruleID)
	return nil
}

// UpdateAccount updates the name of an existing account.
func (c *httpClient) UpdateAccount(accountID string, newName string) error {
	if accountID == "" {
		err := fmt.Errorf("accountID cannot be empty for UpdateAccount")
		c.logger.Error("Validation failed for UpdateAccount", "event", "ValidationError", "error", err)
		return err
	}
	url := fmt.Sprintf("%sbudgets/%s/accounts/%s",
		c.config.BaseURL,
		c.config.BudgetID,
		accountID,
	)
	reqBody := model.UpdateAccountRequest{}
	reqBody.Account.Name = newName
	body, err := json.Marshal(reqBody)
	if err != nil {
		c.logger.Error("Failed to marshal UpdateAccount request", "event", "MarshalError", "account_id", accountID, "error", err)
		return fmt.Errorf("marshaling UpdateAccount request failed: %w", err)
	}

	resp, err := c.doRequest("PATCH", url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed updating account %s: %w", accountID, err)
	}
	defer resp.Body.Close()
	c.logger.Debug("Successfully updated account", "event", "UpdateAccountSuccess", "account_id", accountID)
	return nil
}

// GetTransactions retrieves transactions for a specific account within a given date range.
// sinceDate and untilDate should be in "YYYY-MM-DD" format. They are optional.
func (c *httpClient) GetTransactions(accountID, sinceDate, untilDate string) ([]model.Transaction, error) {
	if accountID == "" {
		err := fmt.Errorf("accountID cannot be empty for GetTransactions")
		c.logger.Error("Validation failed for GetTransactions", "event", "ValidationError", "error", err)
		return nil, err
	}
	baseURL := fmt.Sprintf("%sbudgets/%s/accounts/%s/transactions",
		c.config.BaseURL,
		c.config.BudgetID,
		accountID,
	)
	var queryParams []string
	if sinceDate != "" {
		queryParams = append(queryParams, fmt.Sprintf("since_date=%s", sinceDate))
	}
	if untilDate != "" {
		queryParams = append(queryParams, fmt.Sprintf("until_date=%s", untilDate))
	}
	url := baseURL
	if len(queryParams) > 0 {
		url += "?" + strings.Join(queryParams, "&")
	}

	resp, err := c.doRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed getting transactions for account %s: %w", accountID, err)
	}
	defer resp.Body.Close()

	var response model.TransactionsResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		c.logger.Error("Failed to decode transactions response", "event", "DecodeError", "account_id", accountID, "url", url, "error", err)
		return nil, fmt.Errorf("decoding transactions response failed for account %s: %w", accountID, err)
	}
	c.logger.Debug("Successfully fetched transactions", "event", "GetTransactionsSuccess", "account_id", accountID, "since", sinceDate, "until", untilDate, "count", len(response.Data))
	return response.Data, nil
}

// DeleteTransaction deletes a transaction by its ID.
func (c *httpClient) DeleteTransaction(transactionID string) error {
	if transactionID == "" {
		err := fmt.Errorf("transactionID cannot be empty for DeleteTransaction")
		c.logger.Error("Validation failed for DeleteTransaction", "event", "ValidationError", "error", err)
		return err
	}
	url := fmt.Sprintf("%sbudgets/%s/transactions/%s",
		c.config.BaseURL,
		c.config.BudgetID,
		transactionID,
	)
	resp, err := c.doRequest("DELETE", url, nil)
	if err != nil {
		return fmt.Errorf("failed deleting transaction %s: %w", transactionID, err)
	}
	defer resp.Body.Close()
	c.logger.Debug("Successfully deleted transaction", "event", "DeleteTransactionSuccess", "transaction_id", transactionID)
	return nil
}

// Ensure implementation satisfies the interface
var _ Client = (*httpClient)(nil)
