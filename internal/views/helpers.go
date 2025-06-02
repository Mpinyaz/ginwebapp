package views

import "github.com/Mpinyaz/GinWebApp/internal/dtos"

func HasFormError(formData dtos.FormData, field string) bool {
	errors, exists := formData.Errors[field]
	return exists && len(errors) > 0
}

func GetFormErrors(formData dtos.FormData, field string) []string {
	if errors, exists := formData.Errors[field]; exists && len(errors) > 0 {
		return errors
	}
	return []string{}
}

func GetFormError(formData dtos.FormData, field string) string {
	if errors, exists := formData.Errors[field]; exists && len(errors) > 0 {
		return errors[0] // Return the first error message for single error display
	}
	return ""
}

func GetFormValue(formData dtos.FormData, field string) string {
	if value, exists := formData.Values[field]; exists {
		return value
	}
	return ""
}

func InputStyle(formData dtos.FormData, field string) string {
	baseClasses := "w-full px-4 py-3 border rounded-xl focus:ring-2 transition-all duration-200 placeholder-gray-400"

	if HasFormError(formData, field) {
		return baseClasses + " border-red-300 focus:ring-red-500 focus:border-red-500 bg-red-50"
	}
	return baseClasses + " border-gray-300 focus:ring-orange-500 focus:border-orange-500 bg-gray-50"
}
