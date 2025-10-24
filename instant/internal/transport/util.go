package transport

func excludeIntersection(first []int, second []int) ([]int, error) {
	firstMap := make(map[int]bool)
	for _, v := range first {
		firstMap[v] = true
	}

	var result []int
	for _, v := range second {
		if !firstMap[v] {
			result = append(result, v)
		}
	}

	return result, nil
}