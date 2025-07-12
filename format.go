package dns

import (
	"reflect"
	"strconv"
)

// NumField returns the number of rdata fields r has.
func NumField(r RR) int {
	return reflect.ValueOf(r).Elem().NumField() - 1 // Remove RR_Header
}

// Field returns the rdata field i as a string. Fields are indexed starting from 1.
// RR types that holds slice data, for instance the NSEC type bitmap will return a single
// string where the types are concatenated using a space.
// Accessing non existing fields will cause a panic.
func Field(r RR, i int) string {
	if i == 0 {
		return ""
	}
	d := reflect.ValueOf(r).Elem().Field(i)
	switch d.Kind() {
	case reflect.String:
		return d.String()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return strconv.FormatInt(d.Int(), 10)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return strconv.FormatUint(d.Uint(), 10)
	case reflect.Struct:
		switch rrT := r.(type) {
		case *A:
			if rrT.A.IsValid() {
				return rrT.A.String()
			}
		case *AAAA:
			if rrT.AAAA.IsValid() {
				return rrT.AAAA.String()
			}
		}
	case reflect.Slice:
		switch reflect.ValueOf(r).Elem().Type().Field(i).Tag {
		case `dns:"nsec"`:
			if d.Len() == 0 {
				return ""
			}
			s := Type(d.Index(0).Uint()).String()
			for i := 1; i < d.Len(); i++ {
				s += " " + Type(d.Index(i).Uint()).String()
			}
			return s
		default:
			// if it does not have a tag its a string slice
			fallthrough
		case `dns:"txt"`:
			if d.Len() == 0 {
				return ""
			}
			s := d.Index(0).String()
			for i := 1; i < d.Len(); i++ {
				s += " " + d.Index(i).String()
			}
			return s
		}
	}
	return ""
}
