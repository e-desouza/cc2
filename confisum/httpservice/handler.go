package httpservice

import (
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/btcsuite/btcd/btcec"
	"github.com/san-lab/commongo/gohttpservice/templates"
	"github.com/san-lab/commongo/jafgoecies/ecies"
)

var InTEE bool

type myHandler struct {
	Renderer *templates.Renderer
	chamber  *chamber
}

var playercount = 3

func NewHandler() *myHandler {
	mh := new(myHandler)
	mh.Renderer = templates.NewRenderer()
	mh.chamber = NewChamber(playercount)
	return mh
}

type t1 struct {
	Chamber *chamber
	Start   int
	Stop    int
	Count   int
}

func (mh *myHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	data := new(templates.RenderData)
	path := r.URL.Path[1:]
	data.User, _, _ = r.BasicAuth()
	data.HeaderData = struct {
		User  string
		InTEE bool
	}{data.User, InTEE}

	r.ParseForm()

	switch path {
	case "loadtemplates":
		mh.Renderer.LoadTemplates()
	case "chamber":
		mh.chamber.process(r, data)
	case "newsession":
		countpar := r.FormValue("count")
		var err error
		playercount, err = strconv.Atoi(countpar)
		if err != nil {
			playercount = 3
		}
		mh.chamber = NewChamber(playercount)
		data.TemplateName = "home"
		data.BodyData = t1{mh.chamber, 0, playercount, playercount}
	default:
		data.TemplateName = "home"
		data.BodyData = t1{mh.chamber, 0, playercount, playercount}
	}

	mh.Renderer.RenderResponse(w, *data)
	if r.URL.Path[1:] == "EXIT" {
		os.Exit(0)
	}
}

func NewChamber(n int) *chamber {
	ch := new(chamber)
	ch.PlayersCount = n
	ch.Inputs = make([]SafeInput, n, n)
	for n := range ch.Inputs {
		ch.Inputs[n].PlayerName += string(65 + n) //A, B, C...
	}
	ch.PrivateOutputs = make([]string, n, n)
	ch.servkey, _ = btcec.NewPrivateKey(btcec.S256())
	return ch
}

type chamber struct {
	servkey        *btcec.PrivateKey
	PlayersCount   int
	Inputs         []SafeInput
	PrivateOutputs []string
	Error          error
}

type SafeInput struct {
	PlayerName   string
	Input        string
	PublicKey    *btcec.PublicKey
	Signature    *btcec.Signature
	decodedInput string
	Error        error
	Timestamp    time.Time
}

func (ch *chamber) ServerPubKey() string {
	if ch.servkey == nil {
		return "Not set"
	} else {
		return hex.EncodeToString(ch.servkey.PubKey().SerializeUncompressed())
	}
}

func (sfi *SafeInput) PlayerPubKey() string {
	if sfi.PublicKey == nil {
		return "Not set"
	} else {
		return hex.EncodeToString(sfi.PublicKey.SerializeUncompressed())
	}

}

func (sfi *SafeInput) SignatureTxt() string {
	if sfi.Error != nil {
		return fmt.Sprint(sfi.Error)
	}
	if sfi.Signature == nil {
		return "N/A"
	}
	return hex.EncodeToString(sfi.Signature.Serialize())
}

func (ch *chamber) process(r *http.Request, data *templates.RenderData) {

	//Potentially slice the Inputs table
	start := 0
	count := len(ch.Inputs)

	playerdx := r.FormValue("playerno")
	idx, err := strconv.Atoi(playerdx)
	if err == nil && idx < count {
		start = idx
		count = 1 //The new default is "show just one", unless...
	}
	playercount := r.FormValue("playercount")

	idx, err = strconv.Atoi(playercount)

	if err == nil && idx+start <= len(ch.Inputs) {
		count = idx
	}

	for idx := start; idx < start+count; idx++ {
		if ch.Inputs[idx].Signature != nil { //Do not touch already submitted, properly sgned inputs
			continue
		}
		ch.Inputs[idx].Error = nil
		key := "input" + ch.Inputs[idx].PlayerName
		encmessage := r.FormValue(key)
		//fmt.Println(key, encmessage)
		if encmessage == "" {
			continue
		}
		ch.Inputs[idx].Input = encmessage
		var bts, pbts []byte
		bts, err := hex.DecodeString(encmessage)
		if err == nil {
			pbts, err = ecies.ECDecryptPriv(ch.servkey, bts, false)
		}
		if err != nil {
			ch.Inputs[idx].Error = fmt.Errorf("A small Error decoding Intput%v %s", idx, err)
		} else {
			ch.Inputs[idx].decodedInput = string(pbts)
		}
		if err != nil {
			continue
		}
		//Parse public key
		keypkey := "playerpub" + ch.Inputs[idx].PlayerName
		pubstr := r.FormValue(keypkey)
		var pubk *btcec.PublicKey
		if len(pubstr) == 2*65 {

			bts, err = hex.DecodeString(pubstr)
			pubk, err = btcec.ParsePubKey(bts, btcec.S256())
		} else {
			err = fmt.Errorf("Invalid Public Key length")
		}
		if err != nil {
			ch.Inputs[idx].Error = fmt.Errorf("A small problem decoding PubKey %s %s", ch.Inputs[idx].PlayerName, err)
		} else {
			ch.Inputs[idx].PublicKey = pubk
		}
		if err != nil {
			continue
		}
		//Parse signature
		var sig *btcec.Signature
		sigstr := r.FormValue("signature" + ch.Inputs[idx].PlayerName)
		bts, err = hex.DecodeString(sigstr)
		sig, err = btcec.ParseSignature(bts, btcec.S256())
		if err != nil {
			ch.Inputs[idx].Error = fmt.Errorf("A small Eproblem decoding Signature %s %s", ch.Inputs[idx].PlayerName, err)
		} else {
			ch.Inputs[idx].Signature = sig
			ch.Inputs[idx].Timestamp = time.Now()
		}

	}

	data.BodyData = t1{ch, start, start + count, count}

}

func (ch *chamber) Output() string {
	missingInputs0 := "Missing inputs "
	missingInputs := missingInputs0
	for _, i := range ch.Inputs {
		if i.Signature == nil {
			missingInputs += "from " + i.PlayerName + ","
		}
	}
	if len(missingInputs) > len(missingInputs0) {
		return missingInputs
	}
	parsingError0 := "Error parsing input "
	parsingError := parsingError0
	ss := 0
	for _, i := range ch.Inputs {
		s, err := strconv.Atoi(i.decodedInput)
		if err != nil {
			parsingError += "from " + i.PlayerName + ","
		} else {
			ss += s
		}
	}
	if len(parsingError) > len(parsingError0) {
		return parsingError
	}
	out1, err := ecies.ECEncryptPub(ch.Inputs[0].PublicKey, []byte("You are the gratest!"), false)
	if err != nil {
		ch.PrivateOutputs[0] = fmt.Sprint(err)
	} else {
		ch.PrivateOutputs[0] = hex.EncodeToString(out1)
	}
	return strconv.Itoa(ss)
}
