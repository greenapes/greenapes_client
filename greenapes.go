package greenapes

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

type RoundTripper struct {
	http.Transport
	server     *ApiServer
	User_token string
}

func (self *RoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme == "" {
		u, err := url.Parse(self.server.remote_url + req.URL.Path + "?" + req.URL.RawQuery)
		if err != nil {
			return nil, err
		}
		req.URL = u
	}
	req.SetBasicAuth(self.server.app_id, self.server.app_secret)
	if self.User_token != "" {
		req.Header.Set("X-User-Token", self.User_token)
	}
	if req.Header.Get("Accept") == "" {
		req.Header.Set("Accept", "application/javascript")
	}
	return self.Transport.RoundTrip(req)
}

type Error struct {
	StatusCode int
	//body       string
}

func (self *Error) Error() string {
	var code string
	if self.StatusCode == 0 {
		code = "internal-error"
	} else {
		code = strconv.FormatInt(int64(self.StatusCode), 10)
	}
	return fmt.Sprintf("Greenapes error[%s]", code)
}

func ExtractStatusCode(e error) int {
	g, ok := e.(*Error)
	if ok {
		return g.StatusCode
	} else {
		return 0
	}
}

type ApiServer struct {
	remote_url string
	app_id     string
	app_secret string
}

func NewApiServer(url, app_id, app_secret string) *ApiServer {
	return &ApiServer{
		remote_url: url,
		app_id:     app_id,
		app_secret: app_secret,
	}
}

func (self *ApiServer) Client(user_token string) *NetworkClient {
	return &NetworkClient{
		&http.Client{
			Transport: &RoundTripper{
				server:     self,
				User_token: user_token,
			},
		},
		self,
	}
}

func (self *ApiServer) AnonymousClient() *NetworkClient {
	return self.Client("")
}

type NetworkClient struct {
	*http.Client
	server *ApiServer
}

func (self *NetworkClient) fix_url(u string) string {
	if strings.HasPrefix(u, "/") {
		u = self.server.remote_url + u
	}
	return u
}

func (self *NetworkClient) GetData(u string, v interface{}) error {
	u = self.fix_url(u)
	resp, err := self.Get(u)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return &Error{resp.StatusCode}
	}

	bytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	err = json.Unmarshal(bytes, v)
	if err != nil {
		return err
	}
	return nil
}

func (self *NetworkClient) PostData(u string, v interface{}) error {
	u = self.fix_url(u)
	octets, err := json.Marshal(v)
	if err != nil {
		return err
	}
	resp, err := self.Post(u, "application/javascript", bytes.NewReader(octets))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return &Error{resp.StatusCode}
	}
	return nil
}

func (self *NetworkClient) Delete(u string) error {
	u = self.fix_url(u)
	req, err := http.NewRequest("DELETE", u, nil)
	if err != nil {
		return err
	}
	resp, err := self.Do(req)
	if resp.StatusCode >= 300 {
		return &Error{resp.StatusCode}
	}
	return nil
}
