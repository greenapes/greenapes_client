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

func (self *NetworkClient) GetData(u string, response interface{}) error {
	hresp, err := self.sendRequest("GET", u, nil)
	if err == nil {
		err = self.decodeResponse(hresp, response)
	}
	return err
}

func (self *NetworkClient) PostData(u string, body interface{}, response interface{}) error {
	hresp, err := self.sendRequest("POST", u, body)
	if err == nil {
		err = self.decodeResponse(hresp, response)
	}
	return err
}

func (self *NetworkClient) PutData(u string, body interface{}, response interface{}) error {
	hresp, err := self.sendRequest("PUT", u, body)
	if err == nil {
		err = self.decodeResponse(hresp, response)
	}
	return err
}

func (self *NetworkClient) sendRequest(method, u string, body interface{}) (*http.Response, error) {
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
	return self.Do(req)
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