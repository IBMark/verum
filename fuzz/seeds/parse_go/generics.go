package p

type N interface{ ~int | ~float64 }

func Sum[T N](xs []T) T {
	var s T
	for _, x := range xs {
		s += x
	}
	return s
}
