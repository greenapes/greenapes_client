package greenapes

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
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
	StatusCode  int
	Description string
	Details     map[string]interface{}
}

func (self *Error) Error() string {
	var code string
	if self.StatusCode == 0 {
		code = "internal-error"
	} else {
		code = strconv.FormatInt(int64(self.StatusCode), 10)
	}
	return fmt.Sprintf("Greenapes error[code=%s desc=%s]", code, self.Description)
}

func ExtractStatusCode(e error) int {
	g, ok := e.(*Error)
	if ok {
		return g.StatusCode
	} else {
		return 0
	}
}

type LoginRequest struct {
	Timezone  string `json:"timezone"`
	Language  string `json:"language"`
	ClientIp  string
	AcceptTou bool
}

type FBLoginRequest struct {
	LoginRequest
	FBToken string `json:"fbtoken"`
}

type AppleLoginRequest struct {
	LoginRequest
	AppleToken   string `json:"appletoken"`
	AppleIdToken string `json:"appleidtoken"`
}

type GoogleLoginRequest struct {
	LoginRequest
	GoogleToken string `json:"googletoken"`
}

type SmsLoginFirstRequest struct {
	LoginRequest
	Telephone       string `json:"telephone"`
	RecaptchaToken  string `json:"recaptchaToken"`
	BypassRecaptcha string `json:"bypassRecaptcha"`
}

type SmsLoginSecondRequest struct {
	LoginRequest
	Telephone string `json:"telephone"`
	Code      string `json:"code"`
}

type LoginResponse struct {
	UserToken string   `json:"user-token"`
	Email     string   `json:"email"`
	Username  string   `json:"username"`
	Timezone  string   `json:"timezone"`
	Language  string   `json:"language"`
	Profiles  []string `json:"profiles"`
	Created   bool     `json:"created"`
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

func (self *ApiServer) FBLogin(req FBLoginRequest) (LoginResponse, error) {
	resp := LoginResponse{}

	client := self.AnonymousClient()

	path := "/v1/apes/login"
	if req.AcceptTou {
		path += "?tou="
	}

	pending, err := client.prepareRequest("POST", path, req)
	if err != nil {
		return resp, err
	}
	if req.ClientIp != "" {
		pending.Header.Set("X-Client-IP", req.ClientIp)
	}
	_, err = client.doRequest(pending, &resp)
	return resp, err
}

func (self *ApiServer) AppleLogin(req AppleLoginRequest) (LoginResponse, error) {
	resp := LoginResponse{}

	client := self.AnonymousClient()

	path := "/v1/apes/login"
	if req.AcceptTou {
		path += "?tou="
	}

	pending, err := client.prepareRequest("POST", path, req)
	if err != nil {
		return resp, err
	}
	if req.ClientIp != "" {
		pending.Header.Set("X-Client-IP", req.ClientIp)
	}
	_, err = client.doRequest(pending, &resp)
	return resp, err
}

func (self *ApiServer) GoogleLogin(req GoogleLoginRequest) (LoginResponse, error) {
	resp := LoginResponse{}

	client := self.AnonymousClient()

	path := "/v1/apes/login"
	if req.AcceptTou {
		path += "?tou="
	}

	pending, err := client.prepareRequest("POST", path, req)
	if err != nil {
		return resp, err
	}
	if req.ClientIp != "" {
		pending.Header.Set("X-Client-IP", req.ClientIp)
	}
	_, err = client.doRequest(pending, &resp)
	return resp, err
}

func (self *ApiServer) SmsLoginStep1(req SmsLoginFirstRequest) error {
	var resp interface{}

	path := "/v1/apes/login"
	if req.AcceptTou {
		path += "?tou="
	}

	client := self.AnonymousClient()
	code, err := client.PostData(path, req, &resp)
	if err == nil && code != 202 {
		err = fmt.Errorf("invalid status code. received=%v expected=202", code)
	}
	return err
}

func (self *ApiServer) SmsLoginStep1Voice(req SmsLoginFirstRequest) error {
	var resp interface{}
	extended := struct {
		SmsLoginFirstRequest
		Call string `json:"call_me"`
	}{req, ""}

	path := "/v1/apes/login"
	if req.AcceptTou {
		path += "?tou="
	}

	client := self.AnonymousClient()
	code, err := client.PostData(path, extended, &resp)
	if err == nil && code != 202 {
		err = fmt.Errorf("invalid status code. received=%v expected=202", code)
	}
	return err
}

func (self *ApiServer) SmsLoginStep2(req SmsLoginSecondRequest) (LoginResponse, error) {
	resp := LoginResponse{}

	path := "/v1/apes/login"
	if req.AcceptTou {
		path += "?tou="
	}

	client := self.AnonymousClient()
	pending, err := client.prepareRequest("POST", path, req)
	if err != nil {
		return resp, err
	}
	if req.ClientIp != "" {
		pending.Header.Set("X-Client-IP", req.ClientIp)
	}
	_, err = client.doRequest(pending, &resp)
	return resp, err
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

func (self *NetworkClient) HeadData(u string) (int, error) {
	hresp, err := self.sendRequest("HEAD", u, nil, nil)
	return hresp.StatusCode, err
}

func (self *NetworkClient) GetData(u string, response interface{}) (int, error) {
	hresp, err := self.sendRequest("GET", u, nil, response)
	return hresp.StatusCode, err
}

func (self *NetworkClient) PostData(u string, body interface{}, response interface{}) (int, error) {
	hresp, err := self.sendRequest("POST", u, body, response)
	return hresp.StatusCode, err
}

func (self *NetworkClient) PutData(u string, body interface{}, response interface{}) (int, error) {
	hresp, err := self.sendRequest("PUT", u, body, response)
	return hresp.StatusCode, err
}

func (self *NetworkClient) DeleteData(u string) (int, error) {
	hresp, err := self.sendRequest("DELETE", u, nil, nil)
	return hresp.StatusCode, err
}

func (self *NetworkClient) prepareRequest(method, u string, body interface{}) (*http.Request, error) {
	u = self.fix_url(u)
	var payload io.Reader
	if body != nil {
		octets, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		payload = bytes.NewReader(octets)
	}

	req, err := http.NewRequest(method, u, payload)
	if err != nil {
		return nil, err
	}
	req.Header.Set("content-type", "application/javascript")
	return req, nil
}

func (self *NetworkClient) doRequest(req *http.Request, response interface{}) (int, error) {
	hresp, err := self.Do(req)
	if err == nil {
		err = self.decodeResponse(hresp, response)
	}
	return hresp.StatusCode, err
}

func (self *NetworkClient) sendRequest(method, u string, body interface{}, response interface{}) (*http.Response, error) {
	req, err := self.prepareRequest(method, u, body)
	if err != nil {
		return nil, err
	}
	resp, err := self.Do(req)
	if err != nil {
		return nil, err
	}
	if response != nil {
		err = self.decodeResponse(resp, response)
	} else {
		err = self.decodeError(resp)
		resp.Body.Close()
	}
	return resp, err
}

func (self *NetworkClient) decodeResponse(resp *http.Response, decoded interface{}) error {
	defer resp.Body.Close()
	err := self.decodeError(resp)
	if err != nil {
		return err
	}

	if decoded != nil {
		bytes, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}

		err = json.Unmarshal(bytes, decoded)
		if err != nil {
			return err
		}
	}
	return nil
}

func (self *NetworkClient) decodeError(resp *http.Response) error {
	if resp.StatusCode < 400 {
		return nil
	}
	out := &Error{resp.StatusCode, "", nil}

	bytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return out
	}

	var raw struct {
		Error map[string]interface{}
	}

	err = json.Unmarshal(bytes, &raw)
	if err != nil {
		return out
	}

	if raw.Error != nil {
		d, ok := raw.Error["description"]
		if ok {
			out.Description = d.(string)
			delete(raw.Error, "description")
		}
		d, ok := raw.Error["nickname"]
		if ok {
			out.Description = d.(string)
			delete(raw.Error, "nickname")
		}
		out.Details = raw.Error
	}
	return out
}

func (self *NetworkClient) Delete(u string) error {
	u = self.fix_url(u)
	req, err := http.NewRequest("DELETE", u, nil)
	if err != nil {
		return err
	}
	resp, err := self.Do(req)
	if resp.StatusCode >= 300 {
		return &Error{
			StatusCode: resp.StatusCode,
		}
	}
	return nil
}
