package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"golang.org/x/oauth2"
	v2 "google.golang.org/api/oauth2/v2"
)

// ---

func health(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, http.StatusText(http.StatusOK))
}

// ---

const (
	authorizeEndpoint = "https://accounts.google.com/o/oauth2/v2/auth"
	tokenEndpoint     = "https://www.googleapis.com/oauth2/v4/token"
)

var (
	googleClientID     = os.Getenv("GOOGLE_CLIENT_ID")
	googleClientSecret = os.Getenv("GOOGLE_CLIENT_SECRET")
	googleStateMap     = map[string]bool{}
)

func googleOAuth(w http.ResponseWriter, r *http.Request) {
	state := uuid.New().String()
	googleStateMap[state] = true
	log.Println("state=", state)
	log.Println("redirectURL=", googleConfig().AuthCodeURL(state))
}

func googleCallback(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()

	code := r.FormValue("code")
	state := r.FormValue("state")

	if code == "" || state == "" {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(w, http.StatusText(http.StatusBadRequest))
		return
	}

	if _, ok := googleStateMap[state]; !ok {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintln(w, http.StatusText(http.StatusInternalServerError))
		return
	}
	delete(googleStateMap, state)

	conf := googleConfig()
	token, err := conf.Exchange(ctx, code)
	if err != nil || !token.Valid() {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintln(w, http.StatusText(http.StatusInternalServerError))
		return
	}

	service, _ := v2.New(conf.Client(ctx, token))
	tokenInfo, _ := service.Tokeninfo().AccessToken(token.AccessToken).Context(ctx).Do()

	log.Println("TokenType=", token.TokenType)
	log.Println("AccessToken=", token.AccessToken)
	log.Println("Expiry=", token.Expiry.Format(time.RFC3339))
	log.Println("RefreshToken=", token.RefreshToken)
	log.Println("UserId=", tokenInfo.UserId)
}

func googleConfig() *oauth2.Config {
	return &oauth2.Config{
		ClientID:     googleClientID,
		ClientSecret: googleClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  authorizeEndpoint,
			TokenURL: tokenEndpoint,
		},
		Scopes:      []string{"email"},
		RedirectURL: "http://localhost:3000/auth/google/callback",
	}
}

// ---

const (
	dummyXTokenKey = "xyxyxy"
	adminUserID    = "1"
)

type contextUserID struct{}

func getUserID(ctx context.Context) string {
	return ctx.Value(&contextUserID{}).(string)
}

func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		log.Println("auth middleware")

		// X-TOKEN (仮) による API Key 認証が通る場合, admin 接続とする（というてい）。本来は統一された認証機構で分けるのが正しそう。
		xToken := r.Header.Get("X-TOKEN")
		if xToken == dummyXTokenKey {
			log.Println("access admin")
			next.ServeHTTP(w, r.WithContext(context.WithValue(ctx, &contextUserID{}, adminUserID)))
			return
		}

		accessToken, err := r.Cookie("access_token")
		if err != nil {
			log.Println(err)
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprintln(w, http.StatusText(http.StatusUnauthorized))
			return
		}
		log.Println("token=", accessToken.Value)

		token := &oauth2.Token{
			AccessToken: accessToken.Value,
		}
		conf := googleConfig()
		service, err := v2.New(conf.Client(oauth2.NoContext, token))
		if err != nil {
			log.Println("failed v2.New err=", err)
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprintln(w, http.StatusText(http.StatusUnauthorized))
			return
		}

		tokenInfo, err := service.Tokeninfo().Do()
		if err != nil {
			log.Println("failed Tokeninfo do err=", err)
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprintln(w, http.StatusText(http.StatusUnauthorized))
			return
		}
		log.Println("UserId=", tokenInfo.UserId)

		// 本来であれば複数の OAuth を使うことがあり, 単に userId だとユニークにならないため工夫する必要がある
		next.ServeHTTP(w, r.WithContext(context.WithValue(ctx, &contextUserID{}, tokenInfo.UserId)))
	})
}

// ---

const (
	orderURLBase = "http://localhost:3001/orders"
)

func dummyOrder(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	req, _ := http.NewRequest("POST", orderURLBase+"/dummy", nil)
	req.Header.Set("Authorization", "Bearer "+jwtToken(getUserID(ctx)))
	resp, _ := http.DefaultClient.Do(req)
	fmt.Fprintln(w, resp.Status)
}

func getOrderDetails(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	id := mux.Vars(r)["id"]
	log.Println("id=", id)

	req, _ := http.NewRequest("GET", fmt.Sprintf("%s/%s", orderURLBase, id), nil)
	req.Header.Set("Authorization", "Bearer "+jwtToken(getUserID(ctx)))
	resp, _ := http.DefaultClient.Do(req)
	fmt.Fprintln(w, resp.Status)

	b, _ := ioutil.ReadAll(resp.Body)
	fmt.Fprintln(w, string(b))
}

// ---

const (
	// 本来は秘匿情報なので, 外部から注入する必要がある
	signingKey = "security-sample"
)

func jwtToken(userID string) string {
	type customClaims struct {
		UserID string `json:"user_id"`
		jwt.StandardClaims
	}

	claims := customClaims{
		userID,
		jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour * 12).Unix(),
			Issuer:    "test",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(signingKey))
	if err != nil {
		panic(err)
	}

	return tokenString
}

// ---

func main() {
	r := mux.NewRouter()
	r.HandleFunc("/", health).Methods("GET")
	r.HandleFunc("/auth/google", googleOAuth).Methods("GET")
	r.HandleFunc("/auth/google/callback", googleCallback).Methods("GET")

	subRouter := r.PathPrefix("/v1").Subrouter()
	subRouter.HandleFunc("/orders/{id:[0-9]+}", getOrderDetails).Methods("GET")
	subRouter.HandleFunc("/orders/dummy", dummyOrder).Methods("POST")
	subRouter.Use(AuthMiddleware)

	http.Handle("/", r)
	if err := http.ListenAndServe("localhost:3000", nil); err != nil {
		log.Fatal(err)
	}
}
