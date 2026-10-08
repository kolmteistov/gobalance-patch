package consensus

import (
	"encoding/base64"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestConsensusDoc_GetBlindingParam(t *testing.T) {
	c := ConsensusDoc{}
	pk, _ := base64.StdEncoding.DecodeString("uDrHFYt+kWkB4vCkoXKFXUTm6LxOihUvAkq70nAqgy4=")
	expected, _ := base64.StdEncoding.DecodeString("JCh98DUfWVZlOjOIzgXwMrVvn+27hg1dXTjMO520OYY=")
	assert.Equal(t, expected, c.GetBlindingParam(pk, 19408))
}
