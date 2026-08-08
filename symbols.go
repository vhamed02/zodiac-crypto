package zodiaccrypto

import (
	"encoding/binary"
	"fmt"
	"io"
	"strings"
	"unicode"

	"golang.org/x/text/unicode/norm"
)

const (
	TableSize = 50
	KeySize   = 32
)

var symbolCodepoints = [TableSize]rune{
	'\u25CB', '\u25CF', '\u25B3', '\u25B2', '\u25BD', '\u25BC', '\u25A1', '\u25A0', '\u03A9', '\u21AF',
	'\u2606', '\u2605', '\u2726', '\u2727', '\u2729', '\u272A', '\u2205', '\u2208', '\u2643', '\u03A3',
	'\u272F', '\u2295', '\u2297', '\u2299', '\u2296', '\u2298', '\u229A', '\u229B', '\u229D', '\u229E',
	'\u229F', '\u22A0', '\u22A1', '\u2316', '\u2301', '\u2302', '\u2318', '\u2317', '\u25C8', '\u25C9',
	'\u25CC', '\u25CD', '\u25D0', '\u25D1', '\u25D2', '\u25D3', '\u2662', '\u2667', '\u2664', '\u2660',
}

type symbolTable struct {
	symbols [TableSize]string
	indexes map[string]byte
}

func newSymbolTable(codepoints [TableSize]rune) *symbolTable {
	t := &symbolTable{indexes: make(map[string]byte, TableSize)}
	for i, r := range codepoints {
		s := string(r)
		t.symbols[i] = s
		t.indexes[s] = byte(i)
	}
	return t
}

var defaultTable = newSymbolTable(symbolCodepoints)

func (t *symbolTable) symbol(index byte) string {
	return t.symbols[index]
}

func (t *symbolTable) index(symbol string) (byte, bool) {
	i, ok := t.indexes[symbol]
	return i, ok
}

func (t *symbolTable) indices(symbols []string) ([]byte, error) {
	if len(symbols) != KeySize {
		return nil, fmt.Errorf("expected %d symbols, got %d: %w", KeySize, len(symbols), ErrInvalidSymbols)
	}
	indices := make([]byte, KeySize)
	var seen [TableSize]bool
	for position, raw := range symbols {
		symbol := normalizeSymbol(raw)
		index, ok := t.index(symbol)
		if !ok {
			return nil, fmt.Errorf("symbol at position %d is not part of the table: %w", position+1, ErrInvalidSymbols)
		}
		if seen[index] {
			return nil, fmt.Errorf("symbol at position %d is a duplicate: %w", position+1, ErrInvalidSymbols)
		}
		seen[index] = true
		indices[position] = index
	}
	return indices, nil
}

func (t *symbolTable) generate(random io.Reader) ([]string, []byte, error) {
	pool := make([]byte, TableSize)
	for i := range pool {
		pool[i] = byte(i)
	}
	symbols := make([]string, KeySize)
	indices := make([]byte, KeySize)
	for i := 0; i < KeySize; i++ {
		offset, err := randomIndex(random, TableSize-i)
		if err != nil {
			return nil, nil, err
		}
		pool[i], pool[i+offset] = pool[i+offset], pool[i]
		indices[i] = pool[i]
		symbols[i] = t.symbol(pool[i])
	}
	return symbols, indices, nil
}

func randomIndex(random io.Reader, bound int) (int, error) {
	if bound <= 0 {
		return 0, fmt.Errorf("invalid random bound %d", bound)
	}
	limit := uint32(bound)
	rejectBelow := uint32((uint64(1) << 32) % uint64(limit))
	var buf [4]byte
	for {
		if _, err := io.ReadFull(random, buf[:]); err != nil {
			return 0, fmt.Errorf("random source failure: %w", err)
		}
		value := binary.BigEndian.Uint32(buf[:])
		if value >= rejectBelow {
			return int(value % limit), nil
		}
	}
}

func normalizeSymbol(symbol string) string {
	return norm.NFC.String(symbol)
}

func SymbolTable() []string {
	table := make([]string, TableSize)
	copy(table, defaultTable.symbols[:])
	return table
}

func FormatSymbols(symbols []string) string {
	return strings.Join(symbols, " ")
}

func ParseSymbols(s string) ([]string, error) {
	fields := strings.FieldsFunc(s, unicode.IsSpace)
	symbols := make([]string, len(fields))
	for i, field := range fields {
		symbols[i] = normalizeSymbol(field)
	}
	if _, err := defaultTable.indices(symbols); err != nil {
		return nil, err
	}
	return symbols, nil
}
