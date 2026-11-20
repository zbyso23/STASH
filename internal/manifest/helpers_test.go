package manifest

func (s *State) look(p string) (*Version, bool) {
	v, ok, err := s.Lookup(p)
	if err != nil {
		panic(err)
	}
	return v, ok
}

func (s *State) paths() []string {
	p, err := s.Paths()
	if err != nil {
		panic(err)
	}
	return p
}
