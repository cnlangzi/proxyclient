package xray

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestVmessURL(t *testing.T) {
	u, _ := url.Parse("vmess://ewogICJ2IjogMiwKICAicHMiOiAiVk1FU1Mt5pyq55+lPuW+t+WbvS1ORuino+mUgeW+t+WbveWcsOWMuumdnuiHquWItuWJpy1DaGF0R1BULVRpa1Rvay1Zb3VUdWJlLWRlMDEuc2gtY2xvdWRmbGFyZS5zYnM6MjA5NiIsCiAgImFkZCI6ICJkZTAxLnNoLWNsb3VkZmxhcmUuc2JzIiwKICAicG9ydCI6IDIwOTYsCiAgImlkIjogIjc1YTA4ODVmLTBjYTUtNDJhNC04NjUxLTM5MWNmODE5MzE1NCIsCiAgImFpZCI6IDAsCiAgInNjeSI6ICJhdXRvIiwKICAibmV0IjogIndzIiwKICAidHlwZSI6IG51bGwsCiAgImhvc3QiOiAiZGUwMS5zaC1jbG91ZGZsYXJlLnNicyIsCiAgInBhdGgiOiAiLyIsCiAgInRscyI6IHRydWUsCiAgInNuaSI6ICIiCn0=")

	vmessURL, err := ParseVmessURL(u)
	require.NoError(t, err)
	require.Equal(t, "vmess", vmessURL.Protocol())

	u, _ = url.Parse("vmess://eyJ2IjogIjIiLCAicHMiOiAiXHU1YzcxXHU0ZTFjXHU3NzAxXHU5NzUyXHU1YzliXHU1ZTAyIFx1ODA1NFx1OTAxYSIsICJhZGQiOiAidjQwLmhlZHVpYW4ubGluayIsICJwb3J0IjogIjMwODQwIiwgInR5cGUiOiAibm9uZSIsICJpZCI6ICJjYmIzZjg3Ny1kMWZiLTM0NGMtODdhOS1kMTUzYmZmZDU0ODQiLCAiYWlkIjogIjAiLCAibmV0IjogIndzIiwgInBhdGgiOiAiL2luZGV4IiwgImhvc3QiOiAiYXBpMTAwLWNvcmUtcXVpYy1sZi5hbWVtdi5jb20iLCAidGxzIjogIiJ9")
	vmessURL, err = ParseVmessURL(u)
	require.NoError(t, err)
	require.Equal(t, "vmess", vmessURL.Protocol())
}
