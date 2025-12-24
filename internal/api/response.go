package api

import (
	"encoding/json"
	"net/http"

	"github.com/go-playground/validator/v10"
)

// respondJSON sends a JSON response.
func respondJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	response := Response{
		Success: status >= 200 && status < 300,
		Data:    data,
	}

	json.NewEncoder(w).Encode(response)
}

// respondJSONWithMeta sends a JSON response with pagination metadata.
func respondJSONWithMeta(w http.ResponseWriter, status int, data any, meta *Meta) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	response := Response{
		Success: status >= 200 && status < 300,
		Data:    data,
		Meta:    meta,
	}

	json.NewEncoder(w).Encode(response)
}

// respondError sends an error response.
func respondError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	response := Response{
		Success: false,
		Error: &ErrorInfo{
			Code:    code,
			Message: message,
		},
	}

	json.NewEncoder(w).Encode(response)
}

// respondErrorWithDetails sends an error response with details.
func respondErrorWithDetails(w http.ResponseWriter, status int, code, message string, details map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	response := Response{
		Success: false,
		Error: &ErrorInfo{
			Code:    code,
			Message: message,
			Details: details,
		},
	}

	json.NewEncoder(w).Encode(response)
}

// respondValidationError sends a validation error response.
func respondValidationError(w http.ResponseWriter, err error) {
	details := make(map[string]any)

	if validationErrors, ok := err.(validator.ValidationErrors); ok {
		for _, e := range validationErrors {
			field := e.Field()
			tag := e.Tag()
			details[field] = formatValidationError(tag, e.Param())
		}
	}

	respondErrorWithDetails(w, http.StatusBadRequest, "VALIDATION_ERROR", "request validation failed", details)
}

// formatValidationError formats a validation error message.
func formatValidationError(tag, param string) string {
	switch tag {
	case "required":
		return "this field is required"
	case "email":
		return "must be a valid email address"
	case "min":
		return "must be at least " + param + " characters"
	case "max":
		return "must be at most " + param + " characters"
	case "fqdn":
		return "must be a valid domain name"
	case "uuid":
		return "must be a valid UUID"
	case "url":
		return "must be a valid URL"
	default:
		return "invalid value"
	}
}

// decodeJSON decodes a JSON request body.
func decodeJSON(r *http.Request, v any) error {
	return json.NewDecoder(r.Body).Decode(v)
}
