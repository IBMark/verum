package main

import (
	"fmt"
	"net/http"
)

type Server struct {
	Addr string
}

type Handler interface {
	Serve(w http.ResponseWriter, r *http.Request)
}

func (s *Server) Serve(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, s.Addr)
}

func main() {
	http.HandleFunc("/health", (&Server{Addr: ":8080"}).Serve)
}
