package cs

import (
	"fmt"
	"math/big"

	"github.com/vocdoni/gnark-tiny-prover-g16/hintsolver"
)

// Instruction is the lowest element of a constraint system. It stores just enough data to
// reconstruct a constraint of any shape or a hint at solving time.
type Instruction struct {
	// BlueprintID maps this instruction to a blueprint
	BlueprintID BlueprintID

	// ConstraintOffset stores the starting constraint ID of this instruction.
	// Might not be strictly necessary; but speeds up solver for instructions that represents
	// multiple constraints.
	ConstraintOffset uint32

	// The constraint system stores a single []uint32 calldata slice. StartCallData
	// points to the starting index in the mentioned slice. This avoid storing a slice per
	// instruction (3 * uint64 in memory).
	StartCallData uint64
}

// System contains core elements for a constraint System
type System struct {
	// serialization header
	ScalarField string

	Type int

	Instructions []Instruction
	Blueprints   []Blueprint
	CallData     []uint32 // huge slice.

	// can be != than len(instructions)
	NbConstraints int

	// number of internal wires
	NbInternalVariables int

	// input wires names
	Public, Secret []string

	// maps hintID to hint string identifier
	MHintsDependencies map[hintsolver.HintID]string

	// each level contains independent constraints and can be parallelized
	// it is guaranteed that all dependencies for constraints in a level l are solved
	// in previous levels
	// TODO @gbotrel these are currently updated after we add a constraint.
	// but in case the object is built from a serialized representation
	// we need to init the level builder lbWireLevel from the existing constraints.
	Levels [][]int

	// scalar field
	q      *big.Int `cbor:"-"`
	bitLen int      `cbor:"-"`

	// level builder
	lbWireLevel []int    `cbor:"-"` // at which level we solve a wire. init at -1.
	lbOutputs   []uint32 `cbor:"-"` // wire outputs for current constraint.

	CommitmentInfo Commitment

	genericHint BlueprintID
}

// NewSystem initialize the common structure among constraint system
func NewSystem(scalarField *big.Int, capacity int, t int) System {
	system := System{
		Type:               t,
		ScalarField:        scalarField.Text(16),
		MHintsDependencies: make(map[hintsolver.HintID]string),
		q:                  new(big.Int).Set(scalarField),
		bitLen:             scalarField.BitLen(),
		Instructions:       make([]Instruction, 0, capacity),
		CallData:           make([]uint32, 0, capacity*8),
		lbOutputs:          make([]uint32, 0, 256),
		lbWireLevel:        make([]int, 0, capacity),
		Levels:             make([][]int, 0, capacity/2),
	}
	system.genericHint = system.AddBlueprint(&BlueprintGenericHint{})
	return system
}

func (system *System) GetNbInstructions() int {
	return len(system.Instructions)
}

func (system *System) GetInstruction(id int) Instruction {
	return system.Instructions[id]
}

func (system *System) AddBlueprint(b Blueprint) BlueprintID {
	system.Blueprints = append(system.Blueprints, b)
	return BlueprintID(len(system.Blueprints) - 1)
}

func (system *System) GetNbSecretVariables() int {
	return len(system.Secret)
}
func (system *System) GetNbPublicVariables() int {
	return len(system.Public)
}
func (system *System) GetNbInternalVariables() int {
	return system.NbInternalVariables
}

// CheckSerializationHeader parses the scalar field and gnark version headers
//
// This is meant to be use at the deserialization step, and will error for illegal values
func (system *System) CheckSerializationHeader() error {
	scalarField := new(big.Int)
	_, ok := scalarField.SetString(system.ScalarField, 16)
	if !ok {
		return fmt.Errorf("when parsing serialized modulus: %s", system.ScalarField)
	}
	system.q = new(big.Int).Set(scalarField)
	system.bitLen = system.q.BitLen()
	return nil
}

// GetNbVariables return number of internal, secret and public variables
func (system *System) GetNbVariables() (internal, secret, public int) {
	return system.NbInternalVariables, system.GetNbSecretVariables(), system.GetNbPublicVariables()
}

func (system *System) Field() *big.Int {
	return new(big.Int).Set(system.q)
}

// bitLen returns the number of bits needed to represent a fr.Element
func (system *System) FieldBitLen() int {
	return system.bitLen
}

func (system *System) AddInternalVariable() (idx int) {
	idx = system.NbInternalVariables + system.GetNbPublicVariables() + system.GetNbSecretVariables()
	system.NbInternalVariables++
	return idx
}

func (system *System) AddPublicVariable(name string) (idx int) {
	idx = system.GetNbPublicVariables()
	system.Public = append(system.Public, name)
	return idx
}

func (system *System) AddSecretVariable(name string) (idx int) {
	idx = system.GetNbSecretVariables() + system.GetNbPublicVariables()
	system.Secret = append(system.Secret, name)
	return idx
}

func (system *System) AddCommitment(c Commitment) error {
	if system.CommitmentInfo.Is() {
		return fmt.Errorf("currently only one commitment per circuit is supported")
	}

	system.CommitmentInfo = c

	return nil
}

// VariableToString implements Resolver
func (system *System) VariableToString(vID int) string {
	nbPublic := system.GetNbPublicVariables()
	nbSecret := system.GetNbSecretVariables()

	if vID < nbPublic {
		return system.Public[vID]
	}
	vID -= nbPublic
	if vID < nbSecret {
		return system.Secret[vID]
	}
	vID -= nbSecret
	return fmt.Sprintf("v%d", vID) // TODO @gbotrel  vs strconv.Itoa.
}

// GetCallData re-slice the constraint system full calldata slice with the portion
// related to the instruction. This does not copy and caller should not modify.
func (cs *System) GetCallData(instruction Instruction) []uint32 {
	blueprint := cs.Blueprints[instruction.BlueprintID]
	nbInputs := blueprint.NbInputs()
	if nbInputs < 0 {
		// by convention, we store nbInputs < 0 for non-static input length.
		nbInputs = int(cs.CallData[instruction.StartCallData])
	}
	return cs.CallData[instruction.StartCallData : instruction.StartCallData+uint64(nbInputs)]
}

func (cs *System) compressR1C(c *R1C, bID BlueprintID) Instruction {
	inst := Instruction{
		StartCallData:    uint64(len(cs.CallData)),
		ConstraintOffset: uint32(cs.NbConstraints),
		BlueprintID:      bID,
	}
	blueprint := cs.Blueprints[bID]
	calldata := blueprint.(BlueprintR1C).CompressR1C(c)
	cs.CallData = append(cs.CallData, calldata...)
	cs.NbConstraints += blueprint.NbConstraints()
	return inst
}

func (cs *System) compressHint(hm HintMapping, bID BlueprintID) Instruction {
	inst := Instruction{
		StartCallData:    uint64(len(cs.CallData)),
		ConstraintOffset: uint32(cs.NbConstraints), // unused.
		BlueprintID:      bID,
	}
	blueprint := cs.Blueprints[bID]
	calldata := blueprint.(BlueprintHint).CompressHint(hm)
	cs.CallData = append(cs.CallData, calldata...)
	return inst
}

// GetNbConstraints returns the number of constraints
func (cs *System) GetNbConstraints() int {
	return cs.NbConstraints
}

func (cs *System) CheckUnconstrainedWires() error {
	// TODO @gbotrel
	return nil
}
