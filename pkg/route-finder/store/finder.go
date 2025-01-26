// Package store pkg/route-finder/store/finder.go
package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/skycoin/skywire/pkg/routing"
	"github.com/skycoin/skywire/pkg/skywire-utilities/pkg/cipher"
)

// package level errors
var (
	ErrNoRoute       = errors.New("no route to destination")
	ErrContextClosed = errors.New("context closed or timed out")
)

// GetRoute returns a set of max number routes from source to destination which length is between minLen and
// maxLen
func (g *Graph) GetRoute(ctx context.Context, source, destination cipher.PubKey, minLen, maxLen, number int) (routes []routing.Route, err error) {
	sourceVertex, ok := g.graph[source]
	if !ok {
		return nil, ErrNoRoute
	}

	destinationVertex, ok := g.graph[destination]
	if !ok {
		return nil, ErrNoRoute
	}
	return g.routes(ctx, sourceVertex, destinationVertex, minLen, maxLen, number)
}

func (g *Graph) routes(ctx context.Context, source, destination *vertex, minLen, maxLen, number int) ([]routing.Route, error) {
	type queueElement struct {
		node *vertex
		path []*vertex
	}

	routes := make([]routing.Route, 0)
	queue := []queueElement{{source, []*vertex{source}}}

	visited := make(map[*vertex]bool)
	visited[source] = true

	for len(queue) > 0 && len(routes) < number {
		select {
		case <-ctx.Done():
			return nil, ErrContextClosed
		default:
			// Dequeue the first element
			current := queue[0]
			queue = queue[1:]

			// If the current path exceeds maxHops, skip this path
			if len(current.path)-1 > maxLen {
				continue
			}

			// If we reached the target and the path satisfies minHops, add it to validPaths
			if current.node == destination && len(current.path)-1 >= minLen {
				routes = g.appendRoute(ctx, routes, current.path)
			}
			// Explore all neighbors
			for _, neighbor := range g.graph {
				select {
				case <-ctx.Done():
					return nil, ErrContextClosed
				default:
					if current.node.edge.Hex() == neighbor.edge.Hex() {
						continue
					}
					if !visited[neighbor] {
						visited[neighbor] = true
						newPath := append([]*vertex{}, current.path...)
						if !containsVertex(newPath, neighbor) {
							newPath = append(newPath, neighbor)
							queue = append(queue, queueElement{neighbor, newPath})
						}
						visited[neighbor] = false
					}
				}
			}
		}
	}

	if len(routes) == 0 {
		return nil, fmt.Errorf("no route found from %s to %s with at least %d hops and at most %d hops", source.edge.Hex(), destination.edge.Hex(), minLen, maxLen)
	}

	return routes, nil
}

func (g *Graph) appendRoute(ctx context.Context, routes []routing.Route, path []*vertex) []routing.Route {
	var route routing.Route
	for i, v := range path {
		select {
		case <-ctx.Done():
			return nil
		default:
			if i == len(path)-1 {
				continue
			}
			if _, ok := v.connections[path[i+1].edge]; !ok {
				continue
			}
			hop := routing.Hop{
				From: v.edge,
				To:   path[i+1].edge,
				TpID: v.connections[path[i+1].edge].ID,
			}
			route.Hops = append(route.Hops, hop)
		}
	}
	if len(route.Hops) == len(path)-1 {
		routes = append(routes, route)
	}
	return routes
}

func containsVertex(slice []*vertex, element *vertex) bool {
	for _, item := range slice {
		if item == element {
			return true
		}
	}
	return false
}
