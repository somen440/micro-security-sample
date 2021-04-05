package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/form3tech-oss/jwt-go"
	"github.com/gorilla/mux"
)

// ---

type Order struct {
	ID     int    `json:"id"`
	UserID string `json:"user_id"`
	Menu   string `json:"menu"`
}

type OrderRole int

const (
	Admin      OrderRole = 1
	Consumer   OrderRole = 2
	Restaurant OrderRole = 3
	Courier    OrderRole = 4
)

var (
	orderMap = map[int]*Order{
		1: {
			ID:     1,
			UserID: "12",
			Menu:   "special mix",
		},
	}
	orderRoleMap = map[string]OrderRole{
		"1": Admin,
	}
)

func dummyOrder(w http.ResponseWriter, r *http.Request) {
	id := len(orderMap) + 1
	userID := getUserID(r.Context())
	orderMap[id] = &Order{
		ID:     id,
		UserID: userID,
		Menu:   "tekitou mix",
	}
	log.Println("create dummy id=", id, "userID=", userID)
}

func getOrderDetails(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	id, err := strconv.Atoi(mux.Vars(r)["id"])
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(w, http.StatusText(http.StatusBadRequest))
		return
	}
	log.Println("id=", id)

	order, ok := orderMap[id]
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprintln(w, http.StatusText(http.StatusNotFound))
		return
	}

	userID := getUserID(ctx)
	log.Println("userID=", userID)
	role, ok := orderRoleMap[userID]
	if !ok {
		// 本来登録されてるはずで必ず存在するはずだが仮実装のためない場合顧客扱い
		role = Consumer
	}
	switch role {
	case Admin:
		log.Println("admin なのでチェックスキップ...")
		break
	case Consumer:
		if order.UserID != userID {
			// 顧客の場合, 自分のオーダーしか参照できない
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprintln(w, http.StatusText(http.StatusForbidden))
			return
		}
		break
		// todo: 他...
	}

	if err := json.NewEncoder(w).Encode(order); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintln(w, http.StatusText(http.StatusInternalServerError))
		return
	}
}

// ---

type contextUserID struct{}

func getUserID(ctx context.Context) string {
	return ctx.Value(&contextUserID{}).(string)
}

const (
	// 本来は秘匿情報なので, 外部から注入する必要がある
	signingKey = "security-sample"
)

func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		log.Println("header=", r.Header)

		h := strings.Split(r.Header.Get("Authorization"), " ")
		if strings.ToLower(h[0]) != "bearer" {
			log.Println("invalid header")
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprintln(w, http.StatusText(http.StatusUnauthorized))
			return
		}

		type customClaims struct {
			UserID string `json:"user_id"`
			jwt.StandardClaims
		}

		token, err := jwt.ParseWithClaims(h[1], &customClaims{}, func(token *jwt.Token) (interface{}, error) {
			return []byte(signingKey), nil
		})
		if err != nil {
			log.Println("failed ParseWithClaims err=", err)
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprintln(w, http.StatusText(http.StatusUnauthorized))
			return
		}

		claims, ok := token.Claims.(*customClaims)
		if !ok || !token.Valid {
			log.Println("ng valid ok=", ok, "claims.Valid=", token.Valid)
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprintln(w, http.StatusText(http.StatusUnauthorized))
			return
		}
		log.Println("success auth userID=", claims.UserID)

		next.ServeHTTP(w, r.WithContext(context.WithValue(ctx, &contextUserID{}, claims.UserID)))
	})
}

// ---

func main() {
	r := mux.NewRouter()

	r.HandleFunc("/orders/{id:[0-9]+}", getOrderDetails).Methods("GET")
	r.HandleFunc("/orders/dummy", dummyOrder).Methods("POST")
	r.Use(AuthMiddleware)

	http.Handle("/", r)
	if err := http.ListenAndServe("localhost:3001", nil); err != nil {
		log.Fatal(err)
	}
}
