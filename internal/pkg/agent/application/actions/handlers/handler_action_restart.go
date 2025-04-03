// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package handlers

import (
	"context"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/coordinator"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi/acker"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

type Restart struct {
	log *logger.Logger
	c   *coordinator.Coordinator
}

func NewRestart(log *logger.Logger, c *coordinator.Coordinator) *Restart {
	log.Infof("NEW RESTART")
	return &Restart{
		log: log,
		c:   c,
	}
}

// Handle handles RESTART action.
func (h *Restart) Handle(ctx context.Context, a fleetapi.Action, acker acker.Acker) error {
	h.log.Infof("===== RESTART action starting handle =====\n")

	h.log.Debugf("handlerRestart: action '%+v' received", a)

	// TODO:
	// * Save the action somewhere (state store potentially, restart marker)
	// * Need access to the state store update the NewRestart function and the
	// managedmode
	// * Create restart marker
	// * save action info
	// * Do the ReExec
	// * Read restart marker
	// * ack and commit
	// * delete marker

	// if err := acker.Ack(ctx, a); err != nil {
	// 	h.log.Errorf("failed to acknowledge RESTART action with id '%s'", a.ID)
	// } else if err := acker.Commit(ctx); err != nil {
	// 	h.log.Errorf("failed to commit acker after acknowledging action with id '%s'", a.ID)
	// }

	h.log.Infof("===== RESTART action is not going to be acked =====\n")
	h.log.Infof("===== RESTART action is handled =====\n")

	h.log.Infof("===== restarting the agent =====\n")

	h.c.ReExec(nil)

	return nil
}
