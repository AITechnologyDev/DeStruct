package pipeline

import (
	"testing"

	"github.com/destruct/destruct/internal/flutter/unflutter-0.5.9/internal/cluster"
	"github.com/destruct/destruct/internal/flutter/unflutter-0.5.9/internal/snapshot"
)

// TestResolvePoolDisplay_FieldOwnerQualification covers the libapp.so RSA-slice
// pp+0xb050..pp+0xb0c8 collision: three Field NamedObjects share leaf "uHb" but
// have distinct Class owners (Wja, Yja, aka). The pool dump must distinguish
// them by emitting owner.leaf instead of bare leaf.
func TestResolvePoolDisplay_FieldOwnerQualification(t *testing.T) {
	const (
		fieldCID = 200
		classCID = 100
		// Ref IDs for the three Class owners.
		refClassWja = 10
		refClassYja = 11
		refClassAka = 12
		// Ref IDs for the leaf name strings.
		refNameUhb      = 20
		refNameBmb      = 21
		refNameDigest   = 22
		refNameClassWja = 30
		refNameClassYja = 31
		refNameClassAka = 32
		// Ref IDs for the three uHb Field objects and the _bMb field.
		refFieldWjaUhb = 40
		refFieldYjaUhb = 41
		refFieldAkaUhb = 42
		refFieldAkaBmb = 43
		// Field-with-no-owner case.
		refFieldOrphan = 44
		refNameOrphan  = 45
	)

	ct := &snapshot.CIDTable{Field: fieldCID, Class: classCID}

	classWja := &cluster.NamedObject{CID: classCID, RefID: refClassWja, NameRefID: refNameClassWja, OwnerRefID: -1}
	classYja := &cluster.NamedObject{CID: classCID, RefID: refClassYja, NameRefID: refNameClassYja, OwnerRefID: -1}
	classAka := &cluster.NamedObject{CID: classCID, RefID: refClassAka, NameRefID: refNameClassAka, OwnerRefID: -1}

	fieldWjaUhb := &cluster.NamedObject{CID: fieldCID, RefID: refFieldWjaUhb, NameRefID: refNameUhb, OwnerRefID: refClassWja}
	fieldYjaUhb := &cluster.NamedObject{CID: fieldCID, RefID: refFieldYjaUhb, NameRefID: refNameUhb, OwnerRefID: refClassYja}
	fieldAkaUhb := &cluster.NamedObject{CID: fieldCID, RefID: refFieldAkaUhb, NameRefID: refNameUhb, OwnerRefID: refClassAka}
	fieldAkaBmb := &cluster.NamedObject{CID: fieldCID, RefID: refFieldAkaBmb, NameRefID: refNameBmb, OwnerRefID: refClassAka}
	fieldOrphan := &cluster.NamedObject{CID: fieldCID, RefID: refFieldOrphan, NameRefID: refNameOrphan, OwnerRefID: -1}

	l := &PoolLookups{
		RefToStr: map[int]string{
			refNameUhb:      "uHb",
			refNameBmb:      "_bMb@211060559",
			refNameDigest:   "RSA signing with digest ",
			refNameClassWja: "Wja",
			refNameClassYja: "Yja",
			refNameClassAka: "aka",
			refNameOrphan:   "orphanLeaf",
		},
		RefToNamed: map[int]*cluster.NamedObject{
			refClassWja:    classWja,
			refClassYja:    classYja,
			refClassAka:    classAka,
			refFieldWjaUhb: fieldWjaUhb,
			refFieldYjaUhb: fieldYjaUhb,
			refFieldAkaUhb: fieldAkaUhb,
			refFieldAkaBmb: fieldAkaBmb,
			refFieldOrphan: fieldOrphan,
		},
		RefCID:         map[int]int{},
		CodeRefDisplay: map[int]string{},
		VmRefToStr:     map[int]string{},
		VmRefCID:       map[int]int{},
		VmRefToNamed:   map[int]*cluster.NamedObject{},
		CT:             ct,
	}

	// Pool indices match the libapp.so RSA slice byte offsets
	// (0x10 + index*8): 0xb058,0xb060,0xb068,0xb080,0xb088,0xb098 etc.
	// Only the entries we care about for this test are present.
	const (
		idxWjaUhb = (0xb058 - 0x10) / 8 // 5641
		idxYjaUhb = (0xb060 - 0x10) / 8 // 5642
		idxAkaUhb = (0xb068 - 0x10) / 8 // 5643
		idxRSA    = (0xb080 - 0x10) / 8 // 5646
		idxAkaBmb = (0xb088 - 0x10) / 8 // 5647
		idxOrphan = (0xb0c0 - 0x10) / 8 // 5654
	)
	pool := []cluster.PoolEntry{
		{Index: idxWjaUhb, Kind: cluster.PoolTagged, RefID: refFieldWjaUhb},
		{Index: idxYjaUhb, Kind: cluster.PoolTagged, RefID: refFieldYjaUhb},
		{Index: idxAkaUhb, Kind: cluster.PoolTagged, RefID: refFieldAkaUhb},
		{Index: idxRSA, Kind: cluster.PoolTagged, RefID: refNameDigest},
		{Index: idxAkaBmb, Kind: cluster.PoolTagged, RefID: refFieldAkaBmb},
		{Index: idxOrphan, Kind: cluster.PoolTagged, RefID: refFieldOrphan},
	}

	// Sanity: RefToStr resolves "RSA signing with digest " via its own ref,
	// not via NamedObject. ResolvePoolDisplay's string branch handles it.
	l.RefToStr[refNameDigest] = "RSA signing with digest "

	got := ResolvePoolDisplay(pool, l)

	wants := map[int]string{
		idxWjaUhb: "Wja.uHb",
		idxYjaUhb: "Yja.uHb",
		idxAkaUhb: "aka.uHb",
		idxRSA:    `"RSA signing with digest "`,
		idxAkaBmb: "aka._bMb@211060559",
		idxOrphan: "orphanLeaf", // fallback: no owner → leaf-only
	}
	for idx, want := range wants {
		if got[idx] != want {
			t.Errorf("pool[%d]: got %q want %q", idx, got[idx], want)
		}
	}

	// Collision check: the three uHb entries must be distinct.
	if got[idxWjaUhb] == got[idxYjaUhb] {
		t.Errorf("uHb collision not resolved: pp+0xb058 == pp+0xb060 == %q", got[idxWjaUhb])
	}
	if got[idxYjaUhb] == got[idxAkaUhb] {
		t.Errorf("uHb collision not resolved: pp+0xb060 == pp+0xb068 == %q", got[idxYjaUhb])
	}
}
