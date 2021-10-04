package templates

import (
	"fmt"
	"html/template"
	"io"
)

var Tempts *template.Template

func init() {
	var e error
	Tempts, e = template.New("header").Parse(header)
	if e != nil {
		fmt.Println(e)
	}
	Tempts.New("footer").Parse(footer)
	Tempts.New("home").Parse(home)
	Tempts.New("inputguts").Parse(inputguts)
}

type Renderer struct {
	templates *template.Template
}

func NewRenderer() *Renderer {
	r := &Renderer{}
	r.LoadTemplates()
	return r
}

//Taken out of the constructor with the idea of forced template reloading
func (r *Renderer) LoadTemplates() {
	/*
		var allFiles []string
		files, err := ioutil.ReadDir("./templates")
		if err != nil {
			log.Println(err)
		}
		for _, file := range files {
			filename := file.Name()
			if strings.HasSuffix(filename, ".htemplate") {
				allFiles = append(allFiles, "./templates/"+filename)
			}
		}
		r.templates, err = template.ParseFiles(allFiles...) //parses all .tmpl files in the 'templates' folder
		if err != nil {
			log.Println(err)
		}
	*/
}

func RenderResponse(w io.Writer, data RenderData) error {
	if len(data.TemplateName) < 1 {
		data.TemplateName = "home"
	}
	err := Tempts.ExecuteTemplate(w, data.TemplateName, data)
	if err != nil {
		fmt.Println(err)
	}
	return err

}

//This is a try to bring some uniformity to passing data to the templates
//The "RenderData" container is a wrapper for the header/body/footer containers
type RenderData struct {
	Error        string
	TemplateName string
	User         string
	InTEE        bool
	HeaderData   interface{}
	BodyData     interface{}
	FooterData   interface{}
}

const header = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Tiny Test Server In Memory</title>
</head>
<body >

<a href="/"><h3 style="color: black">Confidential Calculator</h3></a>
<h4>Decrypts and processes encrypted inputs</h4>
{{ if .InTEE}}{{else}}<small>(probably not runing inside TEE...)</small><br/>{{end}}
{{ with .User}}You are logged in as "{{.}}" <br/>{{end}}
<hr/>`

const footer = `<hr/>
Santander Blockchain Center of Excellence

</body>
</html>
`

const home = `{{template "header" .HeaderData}}
{{with .Error}}Error: {{.}}{{end}}



<form action="/chamber?playerno={{.BodyData.Start}}&playercount={{.BodyData.Count}}" method="post"> 
<table  width=800px>
<tr>
<td width=150px valign="top">Session Public Key:</td><td >

<textarea style="border: none; width: 100%; -webkit-box-sizing: border-box; -moz-box-sizing: border-box; box-sizing: border-box;" name="serverpubkey">{{.BodyData.Chamber.ServerPubKey}}</textarea></td>
</tr>
<tr><td colspan=2><hr/></td></tr>
	   {{template "inputguts" (slice .BodyData.Chamber.Inputs .BodyData.Start .BodyData.Stop)}}

<tr>
<td valign="top">Output:</td><td>
{{.BodyData.Chamber.Output}}</td>
</tr>
<tr>
<td valign="top">Private Output A:</td><td>
{{(index .BodyData.Chamber.PrivateOutputs 0)}}</td>
</tr>
<tr>
<td><input type="Submit" value="Submit" /></td><td>{{with .BodyData.Chamber.Error}} {{.}}{{end}}</td>
</tr>

</table>
</form>
{{template "footer" .FooterData}}
`

const inputguts = `
{{range $idx, $input := .}}

<tr>
<td width=150px valign="top">Public Key Player {{$input.PlayerName}}:</td><td >
<textarea style="border: none; width: 100%; -webkit-box-sizing: border-box; -moz-box-sizing: border-box; box-sizing: border-box;" name="playerpub{{$input.PlayerName}}">{{$input.PlayerPubKey}}</textarea></td>
</tr>
<tr>
<td width=150px valign="top" height=80px>Input {{$input.PlayerName}}:</td><td >
<textarea style="border: none; width: 100%; height: 80px; " name="input{{$input.PlayerName}}">{{$input.Input}}</textarea></td>
</tr>
<tr>
<td width=150px valign="top">Signature {{$input.PlayerName}}:</td><td >
<textarea style="border: none; width: 100%; -webkit-box-sizing: border-box; -moz-box-sizing: border-box; box-sizing: border-box;" name="signature{{$input.PlayerName}}">{{$input.SignatureTxt}}</textarea></td>
</tr>
<tr><td colspan=2><hr/></td></tr>
{{end}}
`
