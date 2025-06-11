package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/gotd/td/telegram"
	"github.com/gotd/td/telegram/auth"
	"github.com/gotd/td/telegram/message"
	"github.com/gotd/td/telegram/message/peer"
	"github.com/gotd/td/tg"

	"go.uber.org/zap"
	"nhooyr.io/websocket"
)

// wsRequest represents incoming messages from frontend.
type wsRequest struct {
	Type      string `json:"type"`
	AppID     int    `json:"app_id,omitempty"`
	AppHash   string `json:"app_hash,omitempty"`
	Phone     string `json:"phone,omitempty"`
	Code      string `json:"code,omitempty"`
	Password  string `json:"password,omitempty"`
	Peer      string `json:"peer,omitempty"`
	Message   string `json:"message,omitempty"`
	FirstName string `json:"first_name,omitempty"`
	LastName  string `json:"last_name,omitempty"`
	Limit     int    `json:"limit,omitempty"`
}

// wsResponse represents messages sent to frontend.
type wsResponse struct {
	Type  string      `json:"type"`
	Data  interface{} `json:"data,omitempty"`
	Error string      `json:"error,omitempty"`
}

// dialogInfo is a simplified description of a dialog.
type dialogInfo struct {
	ID   int64  `json:"id"`
	Type string `json:"type"`
	Name string `json:"name"`
}

// historyMsg is a simplified description of a message.
type historyMsg struct {
	ID   int    `json:"id"`
	From int64  `json:"from"`
	Text string `json:"text"`
}

func extractDialogs(res tg.MessagesDialogsClass) []dialogInfo {
	var dialogs []dialogInfo
	var (
		dls      []tg.DialogClass
		entities peer.Entities
	)
	switch r := res.(type) {
	case *tg.MessagesDialogs:
		dls = r.Dialogs
		entities = peer.EntitiesFromResult(r)
	case *tg.MessagesDialogsSlice:
		dls = r.Dialogs
		entities = peer.EntitiesFromResult(r)
	default:
		return dialogs
	}

	for _, d := range dls {
		p, err := entities.ExtractPeer(d.GetPeer())
		if err != nil {
			continue
		}
		info := dialogInfo{}
		switch v := p.(type) {
		case *tg.InputPeerUser:
			info.ID = v.UserID
			info.Type = "user"
			if u, ok := entities.Users()[v.UserID]; ok && u != nil {
				info.Name = strings.TrimSpace(strings.TrimSpace(u.FirstName + " " + u.LastName))
				if info.Name == "" {
					info.Name = u.Username
				}
			}
		case *tg.InputPeerChat:
			info.ID = int64(v.ChatID)
			info.Type = "chat"
			if c, ok := entities.Chats()[v.ChatID]; ok && c != nil {
				info.Name = c.Title
			}
		case *tg.InputPeerChannel:
			info.ID = v.ChannelID
			info.Type = "channel"
			if c, ok := entities.Channels()[v.ChannelID]; ok && c != nil {
				info.Name = c.Title
			}
		default:
			continue
		}
		dialogs = append(dialogs, info)
	}
	return dialogs
}

func extractHistory(res tg.MessagesMessagesClass) []historyMsg {
	var msgs []historyMsg
	var (
		mArr     []tg.MessageClass
		entities peer.Entities
	)
	switch r := res.(type) {
	case *tg.MessagesMessages:
		mArr = r.Messages
		entities = peer.EntitiesFromResult(r)
	case *tg.MessagesMessagesSlice:
		mArr = r.Messages
		entities = peer.EntitiesFromResult(r)
	default:
		return msgs
	}

	for _, m := range mArr {
		msg, ok := m.AsNotEmpty()
		if !ok {
			continue
		}
		hm := historyMsg{ID: msg.GetID(), Text: msg.GetMessage()}
		if from, ok := msg.GetFromID(); ok {
			p, err := entities.ExtractPeer(from)
			if err == nil {
				switch t := p.(type) {
				case *tg.InputPeerUser:
					hm.From = t.UserID
				case *tg.InputPeerChat:
					hm.From = int64(t.ChatID)
				case *tg.InputPeerChannel:
					hm.From = t.ChannelID
				}
			}
		}
		msgs = append(msgs, hm)
	}
	return msgs
}

// wsAuth implements auth.UserAuthenticator over WebSocket.
type wsAuth struct {
	conn       *websocket.Conn
	phone      string
	mu         sync.Mutex
	codeCh     chan string
	passwordCh chan string
	signUpCh   chan auth.UserInfo
}

func newWSAuth(conn *websocket.Conn, phone string) *wsAuth {
	return &wsAuth{
		conn:       conn,
		phone:      phone,
		codeCh:     make(chan string),
		passwordCh: make(chan string),
		signUpCh:   make(chan auth.UserInfo),
	}
}

func (a *wsAuth) send(ctx context.Context, msg wsResponse) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	data, _ := json.Marshal(msg)
	return connWrite(ctx, a.conn, data)
}

func connWrite(ctx context.Context, c *websocket.Conn, data []byte) error {
	return c.Write(ctx, websocket.MessageText, data)
}

func connRead(ctx context.Context, c *websocket.Conn, v interface{}) error {
	_, data, err := c.Read(ctx)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

func (a *wsAuth) Phone(ctx context.Context) (string, error) {
	return a.phone, nil
}

func (a *wsAuth) Code(ctx context.Context, _ *tg.AuthSentCode) (string, error) {
	if err := a.send(ctx, wsResponse{Type: "need_code"}); err != nil {
		return "", err
	}
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case code := <-a.codeCh:
		return code, nil
	}
}

func (a *wsAuth) Password(ctx context.Context) (string, error) {
	if err := a.send(ctx, wsResponse{Type: "need_password"}); err != nil {
		return "", err
	}
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case pwd := <-a.passwordCh:
		return pwd, nil
	}
}

func (a *wsAuth) AcceptTermsOfService(ctx context.Context, tos tg.HelpTermsOfService) error {
	return a.send(ctx, wsResponse{Type: "terms", Data: tos.Text})
}

func (a *wsAuth) SignUp(ctx context.Context) (auth.UserInfo, error) {
	if err := a.send(ctx, wsResponse{Type: "need_signup"}); err != nil {
		return auth.UserInfo{}, err
	}
	select {
	case <-ctx.Done():
		return auth.UserInfo{}, ctx.Err()
	case info := <-a.signUpCh:
		return info, nil
	}
}

// clientSession represents WebSocket client session.
type clientSession struct {
	conn     *websocket.Conn
	auth     *wsAuth
	requests chan wsRequest
	log      *zap.Logger
}

func newClientSession(conn *websocket.Conn, log *zap.Logger) *clientSession {
	return &clientSession{
		conn:     conn,
		requests: make(chan wsRequest, 16),
		log:      log,
	}
}

func (s *clientSession) readLoop(ctx context.Context) {
	for {
		var req wsRequest
		if err := connRead(ctx, s.conn, &req); err != nil {
			s.log.Info("read error", zap.Error(err))
			close(s.requests)
			return
		}
		switch req.Type {
		case "code":
			if s.auth != nil {
				s.auth.codeCh <- req.Code
			}
		case "password":
			if s.auth != nil {
				s.auth.passwordCh <- req.Password
			}
		case "signup":
			if s.auth != nil {
				s.auth.signUpCh <- auth.UserInfo{FirstName: req.FirstName, LastName: req.LastName}
			}
		default:
			s.requests <- req
		}
	}
}

func (s *clientSession) write(ctx context.Context, resp wsResponse) error {
	s.auth.mu.Lock()
	defer s.auth.mu.Unlock()
	data, _ := json.Marshal(resp)
	return connWrite(ctx, s.conn, data)
}

func (s *clientSession) run(ctx context.Context) error {
	defer s.conn.Close(websocket.StatusNormalClosure, "bye")

	// Wait for init message
	var initReq wsRequest
	if err := connRead(ctx, s.conn, &initReq); err != nil {
		return err
	}
	if initReq.Type != "init" {
		return errors.New("expected init message")
	}
	appID := initReq.AppID
	appHash := initReq.AppHash
	phone := initReq.Phone

	sessionFile := filepath.Join("session", phone+".json")
	os.MkdirAll("session", 0700)

	dispatcher := tg.NewUpdateDispatcher()
	dispatcher.OnNewMessage(func(ctx context.Context, e tg.Entities, u *tg.UpdateNewMessage) error {
		m, ok := u.Message.(*tg.Message)
		if !ok || m.Out {
			return nil
		}
		data := struct {
			Text string `json:"text"`
		}{Text: m.Message}
		return s.write(ctx, wsResponse{Type: "update", Data: data})
	})

	options := telegram.Options{
		Logger:         s.log,
		SessionStorage: &telegram.FileSessionStorage{Path: sessionFile},
		UpdateHandler:  dispatcher,
	}

	client := telegram.NewClient(appID, appHash, options)

	s.auth = newWSAuth(s.conn, phone)
	go s.readLoop(ctx)

	return client.Run(ctx, func(ctx context.Context) error {
		flow := auth.NewFlow(s.auth, auth.SendCodeOptions{})
		if err := client.Auth().IfNecessary(ctx, flow); err != nil {
			return err
		}
		api := tg.NewClient(client)
		sender := message.NewSender(api)
		if err := s.write(ctx, wsResponse{Type: "login_success"}); err != nil {
			return err
		}

		for {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case req, ok := <-s.requests:
				if !ok {
					return nil
				}
				switch req.Type {
				case "send":
					if req.Peer == "" || req.Message == "" {
						continue
					}
					p := peer.Resolve(peer.Plain(api), req.Peer)
					input, err := p(ctx)
					if err != nil {
						s.log.Error("resolve", zap.Error(err))
						continue
					}
					// ignoring resolve errors for brevity
					if err := sender.To(input).Text(ctx, req.Message); err != nil {
						s.log.Error("send", zap.Error(err))
					}
				case "dialogs":
					limit := req.Limit
					if limit <= 0 || limit > 100 {
						limit = 20
					}
					res, err := api.MessagesGetDialogs(ctx, &tg.MessagesGetDialogsRequest{Limit: limit})
					if err != nil {
						_ = s.write(ctx, wsResponse{Type: "error", Error: err.Error()})
						continue
					}
					list := extractDialogs(res)
					if err := s.write(ctx, wsResponse{Type: "dialogs", Data: list}); err != nil {
						return err
					}
				case "history":
					if req.Peer == "" {
						continue
					}
					limit := req.Limit
					if limit <= 0 || limit > 50 {
						limit = 20
					}
					p := peer.Resolve(peer.Plain(api), req.Peer)
					input, err := p(ctx)
					if err != nil {
						s.log.Error("resolve", zap.Error(err))
						continue
					}
					h, err := api.MessagesGetHistory(ctx, &tg.MessagesGetHistoryRequest{Peer: input, Limit: limit})
					if err != nil {
						_ = s.write(ctx, wsResponse{Type: "error", Error: err.Error()})
						continue
					}
					msgs := extractHistory(h)
					if err := s.write(ctx, wsResponse{Type: "history", Data: msgs}); err != nil {
						return err
					}
				}
			}
		}
	})
}

func main() {
	log, _ := zap.NewDevelopment()
	defer func() { _ = log.Sync() }()

	http.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			log.Error("accept", zap.Error(err))
			return
		}
		sess := newClientSession(conn, log)
		if err := sess.run(r.Context()); err != nil {
			log.Error("session", zap.Error(err))
		}
	})

	addr := os.Getenv("WS_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	log.Info("listening", zap.String("addr", addr))
	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatal("listen", zap.Error(err))
	}
}
