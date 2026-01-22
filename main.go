package main

import "fmt"
import "net/http"

func main() {
	// This is a placeholder for the main function.

	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Hello, World!")
	})

	http.ListenAndServe(":8080", mux)
}