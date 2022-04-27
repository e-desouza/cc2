package httpservice

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"regexp"

	"github.com/btcsuite/btcd/btcec"
	"github.com/san-lab/commongo/gohttpservice/templates"
	"github.com/san-lab/commongo/jafgoecies/ecies"
)

var InTEE bool

type myHandler struct {
	Renderer *templates.Renderer
}

func NewHandler() *myHandler {
	mh := new(myHandler)
	mh.Renderer = templates.NewRenderer()
	//mh.chamber.playerPrivkey, _ = btcec.NewPrivateKey(btcec.S256())
	return mh
}

func (mh *myHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	data := new(templates.RenderData)
	path := lastWord.FindString(r.URL.Path)
	data.User, _, _ = r.BasicAuth()
	data.HeaderData = struct {
		User  string
		InTEE bool
	}{data.User, InTEE}

	r.ParseForm()
	fmt.Println(path)
	switch path {
	case "/chamber":
		mh.handleChamber(r, data)
	//case "/serverpublic":
	//	fmt.Fprintf(w, "Server Public Key:\n%s\n", mh.chamber.ChamberPub())
	//	return
	case "/loadtemplates":
		mh.Renderer.LoadTemplates()
		fmt.Fprintln(w, "Templates have been reloaded")
		return
	default:
		data.TemplateName = "home"
		data.BodyData = new(chamber)
	}
	//TODO change method args to reference
	mh.Renderer.RenderResponse(w, *data)
	if r.URL.Path[1:] == "EXIT" {
		os.Exit(0)
	}
}

type chamber struct {
	servPubkey         *btcec.PublicKey
	playerPrivkey      *btcec.PrivateKey
	PlainMessage       string
	Ciphertext         string
	Signature          string
	Error              error
	ReturnMessage      string
	PlainReturnMessage string
}

func (ch *chamber) ChamberPub() string {
	if ch.servPubkey == nil {
		return "Not set"
	} else {
		return hex.EncodeToString(ch.servPubkey.SerializeUncompressed())
	}
}

func (ch *chamber) PlayerPub() string {
	if ch.playerPrivkey == nil {
		return "-- Set the Private Key. The Public Key will be calculated automatically ---"
	} else {
		return hex.EncodeToString(ch.playerPrivkey.PubKey().SerializeUncompressed())
	}
}

func (ch *chamber) PlayerPriv() string {
	if ch.playerPrivkey == nil {
		return "Not set"
	} else {
		return hex.EncodeToString(ch.playerPrivkey.Serialize())
	}
}

func (mh *myHandler) handleChamber(r *http.Request, data *templates.RenderData) {
	//Get submitted values
	plaintext := r.FormValue("message")
	chpubtxt := r.FormValue("chamberpubkey")
	sendprivtxt := r.FormValue("senderprivkey")
	//Pad with zeros, if necessary
	sendprivtxt = fmt.Sprintf("%064s", sendprivtxt)
	ch := new(chamber)
	var err error
	//Process
	if chpubtxt != "" { //try to parse as public key
		chpubbytes, err := hex.DecodeString(trimit.FindString(chpubtxt))
		if err != nil {
			ch.Error = fmt.Errorf("Error parsing pubkey: %s", err)
		} else {
			ch.servPubkey, err = btcec.ParsePubKey(chpubbytes, btcec.S256())
			if err != nil {
				ch.Error = fmt.Errorf("Error parsing pubkey: %s", err)
			}

		}
	}
	//Decode the signing key
	if ch.Error == nil && sendprivtxt != "" {
		sprkb, err := hex.DecodeString(sendprivtxt)
		if err != nil {
			ch.Error = fmt.Errorf("Error decoding signing key: %s", err)
		} else {
			ch.playerPrivkey, _ = btcec.PrivKeyFromBytes(btcec.S256(), sprkb)
		}
	}

	//Encrypt
	var ctx []byte
	if plaintext != "" && ch.Error == nil && ch.servPubkey != nil {
		ch.PlainMessage = plaintext
		ctx, err = ecies.ECEncryptPub(ch.servPubkey, []byte(ch.PlainMessage), false)
		if err != nil {
			ch.Error = fmt.Errorf("Error encrypting: %s", err)
		} else {
			ch.Ciphertext = hex.EncodeToString(ctx)
		}
	}

	//Sign
	if ch.Error == nil && ch.playerPrivkey != nil {
		hsh := sha256.Sum256(ctx)
		sig, err := ch.playerPrivkey.Sign(hsh[:])
		if err != nil {
			ch.Error = fmt.Errorf("Error while signing: %s", err)
		} else {
			ch.Signature = hex.EncodeToString(sig.Serialize())
		}
	}

	//Decrypt return message if any and if the key is set
	ch.ReturnMessage = trimit.FindString(r.FormValue("retmessage"))
	if ch.playerPrivkey != nil {

		if ch.ReturnMessage != "" {
			bts, err := hex.DecodeString(ch.ReturnMessage)
			if err == nil {
				bts, err = ecies.ECDecryptPriv(ch.playerPrivkey, bts, false)
			}
			if err == nil {
				ch.PlainReturnMessage = string(bts)
			} else {
				ch.PlainReturnMessage = fmt.Sprint(err)
			}

		}
	}

	//Set htmlForm fields
	ch.PlainMessage = plaintext
	data.BodyData = ch
}

var lastWord *regexp.Regexp
var trimit *regexp.Regexp

func init() {
	lastWord = regexp.MustCompile(`/[\w]*$`)
	trimit = regexp.MustCompile(`[\S]+`)
}
