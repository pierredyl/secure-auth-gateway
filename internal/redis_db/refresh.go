package redis_db

const refreshPrefix = "refresh:"

func RefreshKey(tokenID string) string {
	return refreshPrefix + tokenID
}
