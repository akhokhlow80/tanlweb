package admin

import (
	"akhokhlow80/tanlweb/admin/auth"
	"akhokhlow80/tanlweb/admin/byteunits"
	"akhokhlow80/tanlweb/nodes"
	"akhokhlow80/tanlweb/peers"
	"akhokhlow80/tanlweb/reqlog"
	"akhokhlow80/tanlweb/sqlgen"
	"akhokhlow80/tanlweb/web"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

type deferredPeersLoadFromNode struct {
	NodeUUID string
	NodeName string
	LoadURL  string
}

type deferredPeersLoads struct {
	ShowOwner bool
	Loads     []deferredPeersLoadFromNode
}

func (app *App) deferredPeersLoadsForURL(reqURL func(nodeUUID string) string) []deferredPeersLoadFromNode {
	clients := app.nodeClients.Clients()
	loads := make([]deferredPeersLoadFromNode, 0, len(clients))
	for _, client := range clients {
		loads = append(loads, deferredPeersLoadFromNode{
			NodeUUID: client.Node.UUID.String(),
			NodeName: client.Node.Name,
			LoadURL:  reqURL(client.Node.UUID.String()),
		})
	}
	return loads
}

func (app *App) registerPeerHandlers(m *http.ServeMux) {
	m.HandleFunc("GET /nodes/{node_uuid}/peers",
		web.FailableHandler(app.htmxErrorHandler, app.getPeersFromNodeHandler))
	m.HandleFunc("GET /nodes/{node_uuid}/peers/{pubkey}",
		web.FailableHandler(app.standardErrorHandler, app.getPeerByKeyFromNodeHandler))
	m.HandleFunc("GET /peers",
		web.FailableHandler(app.standardErrorHandler, app.peersPageHandler))
}

type deferredPeersLoadErrorView struct {
	Error    string
	NodeUUID string
}

type peerPrettyTransStat struct {
	Tx string
	Rx string
}

func newPeerPrettyTransStat(stat peers.TransStat) peerPrettyTransStat {
	return peerPrettyTransStat{
		Tx: byteunits.PrettyPrint(stat.Tx),
		Rx: byteunits.PrettyPrint(stat.Rx),
	}
}

type peerWithStatView struct {
	Peer           nodes.PeerFromNode
	MonthTransStat peerPrettyTransStat
}

type peersListFromNodeView struct {
	NodeUUID  string
	ShowOwner bool
	Peers     []peerWithStatView
}

func (app *App) getPeersFromNodeHandler(w http.ResponseWriter, r *http.Request) error {
	if err := authorize(r.Context(), &auth.Scopes{Peers: auth.R}); err != nil {
		return err
	}

	userUUID := r.URL.Query().Get("user_uuid")
	nodeUUID := r.PathValue("node_uuid")

	view, err := func() (peersListFromNodeView, error) {
		client := app.nodeClients.Get(nodeUUID)
		if client == nil {
			return peersListFromNodeView{}, fmt.Errorf("Node not found in cache")
		}

		var (
			peers []nodes.PeerFromNode
			err   error
		)

		peers, err = client.GetPeers(r.Context(), userUUID)
		if err != nil {
			return peersListFromNodeView{}, err
		}
		monthStats, err := client.GetPeerStats(
			r.Context(),
			userUUID,
			time.Now().Add(-30*24*time.Hour),
			time.Time{},
		)
		if err != nil {
			return peersListFromNodeView{}, err
		}

		peersWithStats := make([]peerWithStatView, 0, len(peers))
		for _, peer := range peers {
			peersWithStats = append(peersWithStats, peerWithStatView{
				Peer:           peer,
				MonthTransStat: newPeerPrettyTransStat(monthStats[peer.PublicKey]),
			})
		}

		return peersListFromNodeView{
			NodeUUID:  nodeUUID,
			ShowOwner: userUUID == "",
			Peers:     peersWithStats,
		}, nil
	}()
	if err != nil {
		reqlog.Printf(r, "Loading peers from node failed: %s", err)
		return app.tmpl.ExecuteTemplate(w, "peers/err-from-node", deferredPeersLoadErrorView{
			Error:    err.Error(),
			NodeUUID: nodeUUID,
		})
	}
	return app.tmpl.ExecuteTemplate(w, "peers/list-from-node", view)
}

type peerPage struct {
	R    *http.Request
	Peer nodes.PeerFromNode
}

func (app *App) getPeerByKeyFromNodeHandler(w http.ResponseWriter, r *http.Request) error {
	if err := authorize(r.Context(), &auth.Scopes{Peers: auth.R}); err != nil {
		return err
	}

	nodeUUID := r.PathValue("node_uuid")
	pubkkey := r.PathValue("pubkey")

	client := app.nodeClients.Get(nodeUUID)
	if client == nil {
		return fmt.Errorf("Node not found in cache")
	}

	peer, err := client.GetPeer(r.Context(), pubkkey)
	if err != nil {
		return err
	}
	if peer == nil {
		return errNotFound
	}

	return app.tmpl.ExecuteTemplate(w, "peers/page", peerPage{
		R:    r,
		Peer: *peer,
	})
}

type peersPageView struct {
	R                  *http.Request
	Requests           []peerRequestView
	DeferredPeersLoads []deferredPeersLoadFromNode
}

func (app *App) peersPageHandler(w http.ResponseWriter, r *http.Request) error {
	if err := authorize(r.Context(), &auth.Scopes{Peers: auth.R}); err != nil {
		return err
	}

	dbReqs, err := func() ([]sqlgen.GetPeerRequestsRow, error) {
		app.db.RLock()
		defer app.db.RUnlock()
		return app.db.GetPeerRequests(r.Context())
	}()
	if err != nil {
		return err
	}
	reqs := make([]peerRequestView, 0, len(dbReqs))
	for _, dbReq := range dbReqs {
		req, err := app.parsePeerRequestViewFromDB(&dbReq.PeerRequest, &dbReq.User, &dbReq.Node)
		if err != nil {
			return err
		}
		if req.Status != peers.Pending &&
			req.Status != peers.ConfigRequested &&
			req.Status != peers.Failed {
			continue
		}
		reqs = append(reqs, req)
	}

	return app.tmpl.ExecuteTemplate(w, "peers/list-page", peersPageView{
		R:        r,
		Requests: reqs,
		DeferredPeersLoads: app.deferredPeersLoadsForURL(func(nodeUUID string) string {
			return fmt.Sprintf("nodes/%s/peers", url.PathEscape(nodeUUID))
		}),
	})
}
