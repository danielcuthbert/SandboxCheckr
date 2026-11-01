//go:build !darwin && !linux && !windows

package detect

import (
	"context"

	"github.com/danielcuthbert/sandboxcheckr/internal/model"
)

func collect(context.Context) []model.PostureFinding { return nil }
