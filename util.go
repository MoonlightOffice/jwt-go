package jwt

import (
	"encoding/json"
	"reflect"
	"time"
)

func compareStructs(obj1, obj2 interface{}) bool {
	value1 := reflect.ValueOf(obj1)
	value2 := reflect.ValueOf(obj2)

	// Check if both values are structs
	if value1.Kind() != reflect.Struct || value2.Kind() != reflect.Struct {
		return false
	}

	// Get the type of the structs
	type1 := value1.Type()
	type2 := value2.Type()

	// Check if the structs have the same number of fields
	if type1.NumField() != type2.NumField() {
		return false
	}

	// Iterate over the fields and compare their values
	for i := 0; i < type1.NumField(); i++ {
		field1 := value1.Field(i)
		field2 := value2.Field(i)

		if field1.Type() == reflect.TypeOf(time.Time{}) {
			// Handle time.Time fields separately
			time1 := field1.Interface().(time.Time)
			time2 := field2.Interface().(time.Time)

			// Compare the Unix timestamps of the time values
			if time1.Unix() != time2.Unix() {
				return false
			}
		} else if field1.Kind() == reflect.Struct ||
			field1.Kind() == reflect.Map ||
			field1.Kind() == reflect.Slice ||
			field2.Kind() == reflect.Struct ||
			field2.Kind() == reflect.Map ||
			field2.Kind() == reflect.Slice {
			// Recursively check structs
			ok := almostEqual(field1.Interface(), field2.Interface())
			if !ok {
				return false
			}
		} else {
			// Compare other field values
			if !reflect.DeepEqual(field1.Interface(), field2.Interface()) {
				return false
			}
		}
	}

	return true
}

func almostEqual(obj1, obj2 interface{}) bool {
	j1, err := json.Marshal(obj1)
	if err != nil {
		return false
	}

	j2, err := json.Marshal(obj2)
	if err != nil {
		return false
	}

	if len(string(j1)) != len(string(j2)) {
		return false
	}

	return true
}
