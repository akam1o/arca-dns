package backend

func normalizeListOffset(offset int) int {
	if offset < 0 {
		return 0
	}
	return offset
}
