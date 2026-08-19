package main

import "fmt"

type UserService struct {
	DB interface{}
}

func (s *UserService) GetUserByID(id int) interface{} {
	return nil
}

func (s *UserService) FetchUser(id int) interface{} {
	// Duplicate of GetUserByID
	return nil
}

func (s *UserService) formatLegacyDate(date string) string {
	// Dead code - never called (unexported)
	return date
}

func CalculateTotal(items []map[string]float64) float64 {
	total := 0.0
	for _, item := range items {
		total += item["price"]
	}
	return total
}

func legacyHelper() string {
	// Dead function
	return "deprecated"
}

func main() {
	svc := &UserService{}
	fmt.Println(svc.GetUserByID(1))
	fmt.Println(CalculateTotal(nil))
}
