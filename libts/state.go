package libts

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// Opinionated, sanitized subset of Tailscale state.
type State struct {
	// Tailscale preferences.
	Prefs *ipn.Prefs

	// Current Tailscale backend state.
	BackendState ipn.State

	// Current Tailscale version. This is a shortened version string like "1.70.0".
	TSVersion string

	// Auth URL. Empty if the user doesn't need to be authenticated.
	AuthURL string
	// User profile of the currently logged in user or nil if unknown.
	User *tailcfg.UserProfile

	// Peer status of the local node.
	Self *ipnstate.PeerStatus

	// Tailnet lock key. Nil if not enabled.
	LockKey *key.NLPublic
	// True if the node is locked out by tailnet lock.
	IsLockedOut bool

	// Exit node peers sorted by PeerName.
	ExitNodes []*ipnstate.PeerStatus
	// Peers owned by the user sorted by PeerName.
	MyNodes []*ipnstate.PeerStatus
	// Tagged peers sorted by PeerName.
	TaggedNodes []*ipnstate.PeerStatus
	// Alphabetically sorted keys of AccountNodes.
	OwnedNodeKeys []string
	// Peers owned by other accoutns, sorted by PeerName, and keyed by account name.
	OwnedNodes map[string][]*ipnstate.PeerStatus

	// ID of the currently selected exit node or nil if none is selected.
	CurrentExitNode *tailcfg.StableNodeID
	// Name of the currently selected exit node or an empty string if none is selected.
	CurrentExitNodeName string

	// Total bytes received from peers.
	RxBytes int64
	// Total bytes sent to peers.
	TxBytes int64
}

// Sort a list of node statuses by PeerName.
func sortNodes(nodes []*ipnstate.PeerStatus) {
	slices.SortFunc(nodes, func(a, b *ipnstate.PeerStatus) int {
		return strings.Compare(PeerName(a), PeerName(b))
	})
}

// Create an ipn.State from the string representation.
//
// This string representation comes from Tailscale's API and, because Go does not have
// proper enums, this is the best way to convert it back to a "typed" representation.
func NewIPNStateFromString(v string) (ipn.State, error) {
	switch v {
	case "NoState":
		return ipn.NoState, nil
	case "InUseOtherUser":
		return ipn.InUseOtherUser, nil
	case "NeedsLogin":
		return ipn.NeedsLogin, nil
	case "NeedsMachineAuth":
		return ipn.NeedsMachineAuth, nil
	case "Stopped":
		return ipn.Stopped, nil
	case "Starting":
		return ipn.Starting, nil
	case "Running":
		return ipn.Running, nil
	default:
		return ipn.NoState, fmt.Errorf("unknown ipn state: %s", v)
	}
}

// Make a current State by making necessary Tailscale API calls.
func GetState(ctx context.Context) (State, error) {
	status, err := Status(ctx)
	if err != nil {
		return State{}, err
	}

	prefs, err := Prefs(ctx)
	if err != nil {
		return State{}, err
	}

	lock, err := LockStatus(ctx)
	if err != nil {
		return State{}, err
	}

	backendState, err := NewIPNStateFromString(status.BackendState)
	if err != nil {
		return State{}, fmt.Errorf("cannot get status from state: %w", err)
	}

	state := State{
		Prefs:        prefs,
		AuthURL:      status.AuthURL,
		BackendState: backendState,
		TSVersion:    status.Version,
		Self:         status.Self,
		OwnedNodes:   make(map[string][]*ipnstate.PeerStatus),
	}

	for _, peer := range status.Peer {
		state.TxBytes += peer.TxBytes
		state.RxBytes += peer.RxBytes

		if peer.ExitNodeOption {
			state.ExitNodes = append(state.ExitNodes, peer)
		} else if peer.UserID == status.Self.UserID {
			state.MyNodes = append(state.MyNodes, peer)
		} else if peer.IsTagged() {
			state.TaggedNodes = append(state.TaggedNodes, peer)
		} else {
			var accountName string
			if user, ok := status.User[peer.UserID]; ok {
				accountName = user.DisplayName
				if accountName == "" {
					accountName = user.LoginName
				}
			}

			if _, ok := state.OwnedNodes[accountName]; !ok {
				state.OwnedNodes[accountName] = make([]*ipnstate.PeerStatus, 0)
			}
			state.OwnedNodes[accountName] = append(state.OwnedNodes[accountName], peer)
		}
	}

	sortNodes(state.ExitNodes)
	sortNodes(state.MyNodes)
	sortNodes(state.TaggedNodes)
	for key, value := range state.OwnedNodes {
		sortNodes(value)
		state.OwnedNodeKeys = append(state.OwnedNodeKeys, key)
	}
	slices.Sort(state.OwnedNodeKeys)

	versionSplitIndex := strings.IndexByte(state.TSVersion, '-')
	if versionSplitIndex != -1 {
		state.TSVersion = state.TSVersion[:versionSplitIndex]
	}

	if status.Self != nil {
		user := status.User[status.Self.UserID]
		state.User = &user
	}

	if lock.Enabled && lock.NodeKey != nil && !lock.PublicKey.IsZero() {
		state.LockKey = &lock.PublicKey

		if !lock.NodeKeySigned && state.BackendState == ipn.Running {
			state.IsLockedOut = true
		}
	}

	if status.ExitNodeStatus != nil {
		state.CurrentExitNode = &status.ExitNodeStatus.ID

		for _, peer := range state.ExitNodes {
			if peer.ID == status.ExitNodeStatus.ID {
				state.CurrentExitNodeName = PeerName(peer)
				break
			}
		}
	}

	return state, nil
}
