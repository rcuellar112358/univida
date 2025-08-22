package main

import (
	"bytes"
	"cmp"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"net/mail"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	badger "github.com/dgraph-io/badger/v4"
	"github.com/xuri/excelize/v2"

	"github.com/mojocn/base64Captcha"
)

const (
	certPath                            = "server.crt"
	keyPath                             = "server.key"
	staticDir                           = "static"
	uploadedDir                         = "uploaded"
	puertoServAdmin                     = ":2222"
	MAX_CAPTCHAS_EMITIDOS               = 10000
	TIEMPO_VIGENCIA_CAPTCHA             = 30 * time.Minute
	PASS_DEFAULT                        = "248cff57209766c437a9871a9e6c5597f686b557d2fab79418153b57ed2a2a4b45d8d8b030360d66e925ca43c425355c7bdf79745a10e2a10e8e1824fdec491d"
	REGISTROS_POR_PAGINA_DEFAULT uint32 = 100
	DEFAULT_DATE_LAYOUT                 = `2006-01-02 15:04:05`
	PARSEFORM_LIM                       = 100 << 20
	CORREO_REMITENTE                    = "univida@dinamicamedialab.com"
	PASS_CORREO                         = "6#RzX43|w@Ye"
	SMTP_HOST                           = "buzon.dinamicamedialab.com"
	SUBJECT1                            = `Confirmación de Recepción de Inscripción al Webinar "UNIVIDA S.A. 10 AÑOS, TRANSFORMANDO VIDAS: ACIERTOS Y NUEVAS NECESIDADES DE SEGUROS EN SECTORES VULNERABLES Y POPULARES DE BOLIVIA"`
	BODY1                               = `<!DOCTYPE html>
<html>

<body>
    </div>
	    <div style="text-align: center;">
        <div style="justify-content: center; display: flex;"><img style="margin: auto; margin-top: 2rem;" width=600
                alt="matricula" src="https://dinamicamedialab.com/assets/img/correoUnividaImg5.png">
        </div>
    </div>
    </div>
	    <div style="text-align: center;">
        <div style="justify-content: center; display: flex;"><img style="margin: auto; margin-top: 2rem;" width=600
                alt="matricula" src="https://dinamicamedialab.com/assets/img/correoUnividaImg3.png">
        </div>
    </div>
    <div
        style="color: #333333; border: 1px solid #e6e6e6; padding: 2rem; border-radius: 2rem; max-width:600px; background-color: #fafafa; margin: 1rem auto; text-align: justify;">
        <p>Hola %s,</p>
		<p>Gracias por inscribirte a nuestro próximo webinar. Hemos recibido tu solicitud correctamente y estamos encantados de contar contigo.</p>
		<p>A continuación, te compartimos la información general del evento:</p>
		<p style="font-weight: 700; color: #00455c;">Tema del webinar: "UNIVIDA S.A. 10 AÑOS, TRANSFORMANDO VIDAS: ACIERTOS Y NUEVAS NECESIDADES DE SEGUROS EN SECTORES VULNERABLES Y POPULARES DE BOLIVIA".</p>
		<p>Fecha Webinar I: Miércoles, 3 de Septiembre.</p>
		<p>Fecha Webinar II: Viernes, 5 de Septiembre.</p>
		<p>Hora: 10:00 - 12:00.</p>
		<p>Plataforma: La sesión se llevará a cabo a través de WEBEX</p>
		<p>Para garantizar que tu experiencia en nuestro webinar a través de la plataforma Cisco Webex sea óptima y sin contratiempos, es fundamental que verifiques que tu equipo cumple con los siguientes requisitos técnicos y de hardware.</p>
		<p style="font-weight: 700; color: #00455c;">1. Requisitos de Conectividad y Sistema</p>
		<p>Conexión a Internet: Es el factor más crítico. Se recomienda una conexión de banda ancha estable con al menos 10-25 Mbps de velocidad de subida y bajada para una experiencia de video de alta calidad. Puedes realizar una prueba de velocidad en sitios como speedtest.net.</p>
		<p>Navegadores Web Compatibles (para unirse desde el navegador):</p>
		<p>Google Chrome (versiones más recientes)</p>
		<p>Mozilla Firefox (versiones más recientes)</p>
		<p>Microsoft Edge (versiones más recientes)</p>
		<p style="font-style: oblique; color: #00455c;">Nota: Safari tiene funcionalidades limitadas. Se recomienda utilizar Chrome o Firefox para acceso completo.</p>

		<p style="font-weight: 700; color: #00455c;">2. Requisitos de Hardware</p>
		<p>Computadora:</p>
		<p>PC: Windows 10 o 11.</p>
		<p>Mac: macOS 10.15 (Catalina) o superior.</p>
		<p>Audio:</p>
		<p>Obligatorio: Altavoces o auriculares para escuchar la sesión.</p>
		<p style="font-style: oblique; color: #00455c;">Recomendado: Un micrófono integrado (en la laptop o auriculares) o externo si deseas participar con audio.</p>
		<p>Video (Opcional pero recomendado):</p>
		<p>Una cámara web integrada o externa si deseas activar tu video durante la sesión.</p>

		<p style="font-weight: 700; color: #00455c;">3. Opciones de Participación</p>
		<p>Aplicación de Escritorio (Recomendada): Para la mejor experiencia, con todas las funcionalidades (vista de galería, controles avanzados, etc.), te sugerimos descargar e instalar la aplicación de Webex Meetings con antelación. Es gratuita y está disponible para Windows y Mac.</p>
		<p>Enlace de descarga: https://www.webex.com/downloads.html</p>
		<p>Desde el Navegador Web: Puedes unirte directamente desde Chrome, Firefox o Edge sin necesidad de instalar la aplicación, aunque algunas funciones podrían estar limitadas.</p>
		<p>Dispositivos Móviles: La aplicación Webex está disponible para iOS y Android en sus respectivas tiendas de aplicaciones.</p>
		<p>Una vez confirmados los detalles definitivos (incluyendo fecha, hora, enlace de acceso y agenda específica), te enviaremos un correo 72 horas de antelacion con toda la información necesaria para que puedas unirte sin inconvenientes.</p>
		<p>Si tienes alguna pregunta o necesitas assistance adicional, no dudes en contactarnos respondiendo a este correo.</p>
		<p>¡Esperamos que este webinar sea de gran valor para ti!</p>
		<p>Saludos cordiales</p>
    </div>
    <div style="text-align: center;">
        <div style="justify-content: center; display: flex;"><img style="margin: auto; margin-top: 2rem;" width=800
                alt="matricula" src="https://dinamicamedialab.com/assets/img/correoUnividaImg4.png">
        </div>
    </div>
</body>

</html>`
)

var LA_PAZ_TZ *time.Location

const (
	PERFIL_ADMIN = iota
	PERFIL_USUARIO
)

var PERFIL = map[uint8]string{
	PERFIL_ADMIN:   "Administrador",
	PERFIL_USUARIO: "Usuario",
}

const (
	SESIONES = iota + 1
	USUARIOS
	INSCRITOS
)

var TABLAS = map[uint8]string{
	SESIONES:  "SESIONES",
	USUARIOS:  "USUARIOS",
	INSCRITOS: "INSCRITOS",
}

type Tabla interface {
	Inscrito | Usuario | int
}

type TablaMas interface {
	InscritoMas
}

var USUARIOS_0 = []Usuario{
	{1, PERFIL_ADMIN, "admin", "admin", "347018e671e216d6c0fb9f1b9c0316e6ad53067815b99a40e2e66a7229fc403f9508be43d752d387c362dbf6c969c137818064398f18b5a6bd1cb3130e114f57"},
	{2, PERFIL_USUARIO, "usuario_univida_1", "usuario_univida_1", "928a876997efe2c625821b3679bd3fc58d23bf34bc2998cae304deb52d24108a9959d4464158a008ff18f13084f35931f1e2b005411072bb9e2f2f8bb3d38147"},
}

const (
	DEP_LA_PAZ = iota + 1
	DEP_COCHABAMBA
	DEP_SANTACRUZ
	DEP_ORURO
	DEP_CHUQUISACA
	DEP_PANDO
	DEP_POTOSI
	DEP_TARIJA
	DEP_BENI
)

var DEPARTAMENTOS = map[uint8]string{
	DEP_LA_PAZ:     "La Paz",
	DEP_COCHABAMBA: "Cochabamba",
	DEP_SANTACRUZ:  "Santa Cruz",
	DEP_ORURO:      "Oruro",
	DEP_CHUQUISACA: "Chuquisaca",
	DEP_PANDO:      "Pando",
	DEP_POTOSI:     "Potosí",
	DEP_TARIJA:     "Tarija",
	DEP_BENI:       "Beni",
}

var CONTR_DEPARTAMENTOS = reverseMap(DEPARTAMENTOS)

const (
	EDAD_18_24 = iota + 1
	EDAD_25_34
	EDAD_35_44
	EDAD_45_54
	EDAD_55
)

var EDAD = map[uint8]string{
	EDAD_18_24: "18-24 años",
	EDAD_25_34: "25-34 años",
	EDAD_35_44: "35-44 años",
	EDAD_45_54: "45-54 años",
	EDAD_55:    "55+ años",
}

var CONTR_EDAD = reverseMap(EDAD)

const (
	SEXO_MASCULINO = iota + 1
	SEXO_FEMENINO
	SEXO_OTROS
)

var SEXO = map[uint8]string{
	SEXO_MASCULINO: "Masculino",
	SEXO_FEMENINO:  "Femenino",
	SEXO_OTROS:     "Otros",
}

var CONTR_SEXO = reverseMap(SEXO)

const (
	OCUP_ESTUDIANTE = iota + 1
	OCUP_PROFESIONAL
	OCUP_OTROS
)

var OCUPACIONES = map[uint8]string{
	OCUP_ESTUDIANTE:  "Estudiante",
	OCUP_PROFESIONAL: "Profesional",
	OCUP_OTROS:       "Otros",
}

var CONTR_OCUPACIONES = reverseMap(OCUPACIONES)

type Usuario struct {
	Key            uint64 // FUNCIONA COMO FECHA E IDENTIFICADOR UNICO
	IdPerfil       uint8
	NombreCompleto string
	Username       string
	Password       string
}

type UsuarioMas struct {
	Id      uint32
	Usuario Usuario
	Perfil  string
}

type Inscrito struct {
	Key          uint64
	Nombre       string
	Institucion  string
	Celular      string
	Email        string
	CI           string
	Departamento uint8
	Sexo         uint8
	Edad         uint8
	Ocupacion    uint8
}

type InscritoMas struct {
	Id              uint32
	Inscrito        Inscrito
	DepartamentoStr string
	SexoStr         string
	EdadStr         string
	OcupacionStr    string
}

type Sesion struct {
	IdUsuario uint32
	Valor     string
}

type CaptchaEmitido struct {
	Id            string
	Respuesta     string
	tiempoEmision time.Time
}

var captchasEmitidos []CaptchaEmitido

var mutex_usuarios sync.Mutex
var GLOBAL_usuarios []UsuarioMas
var GLOBAL_contador_usuarios uint32

var mutex_sesiones sync.Mutex
var GLOBAL_sesiones []Sesion

var mutex_inscritos sync.Mutex
var GLOBAL_inscritos []InscritoMas
var GLOBAL_contador_inscritos uint32

func main() {
	//smtpAddr := SMTP_HOST + ":587" // Replace with your SMTP server address and port
	//_, err := smtp.Dial(smtpAddr)
	//if err != nil {
	//	log.Fatal("Error connecting to SMTP server: ", err)
	//}
	//fmt.Printf("Successfully connected to SMTP server at %s\n", smtpAddr)
	// Sera creada si no existe
	opcionesDB := badger.DefaultOptions("./db")
	opcionesDB.ValueLogFileSize = 1<<26 - 1
	opcionesDB.MemTableSize = 16 << 20
	db, err := badger.Open(opcionesDB)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// NOTA: Lo unico que necesito hacer es usar ParseInLocation() en lugar de Parse()
	//LA_PAZ_TZ, err = time.LoadLocation("America/La_Paz")
	//if err != nil {
	//	log.Fatal(err)
	//}

	//time.Local = LA_PAZ_TZ

	crearRegistrosIniciales(db)

	err = iniciarTablasGlobales(db)
	if err != nil {
		fmt.Println("Error al configurar tablas globales: ", err)
	}

	muxPagina := http.NewServeMux()
	muxAdmin := http.NewServeMux()

	muxPagina.HandleFunc("GET /", handleRoot)
	muxPagina.HandleFunc("GET /renovar-captcha", handleRenovarCaptcha)
	muxPagina.HandleFunc("POST /enviar-inscripcion", postEnviarInscripcion(db))

	/* ADMIN */
	P0 := []uint8{PERFIL_ADMIN}
	P_ALL := []uint8{PERFIL_ADMIN, PERFIL_USUARIO}

	muxAdmin.HandleFunc("GET /", esAuth(handleAdminRoot, P_ALL))

	muxAdmin.HandleFunc("GET /login", handleLogin)
	muxAdmin.HandleFunc("POST /credenciales", postCredenciales(db))
	muxAdmin.HandleFunc("GET /cerrar-sesion", handleCerrarSesion)
	muxAdmin.HandleFunc("GET /usuarios", esAuth(handleUsuarios, P0))
	muxAdmin.HandleFunc("GET /agregar-usuario", esAuth(handleAgregarUsuario, P0))
	muxAdmin.HandleFunc("POST /agregar-usuario", esAuthDB(db, postAgregarUsuario, P0))

	muxAdmin.HandleFunc("GET /cambiar-user-password/", esAuth(handleUserPass, P0))
	muxAdmin.HandleFunc("POST /cambiar-user-password/", esAuthDB(db, postCambiarUserPass, P0))
	muxAdmin.HandleFunc("GET /eliminar-usuario/", esAuthDB(db, handleEliminarUsuario, P0))

	muxAdmin.HandleFunc("GET /editar-usuario/", esAuth(handleEditarUsuario, P_ALL))
	muxAdmin.HandleFunc("POST /editar-usuario/", esAuthDB(db, postEditarUsuario, P_ALL))
	muxAdmin.HandleFunc("GET /cambiar-password", esAuth(handleCambiarPass, P_ALL))
	muxAdmin.HandleFunc("POST /cambiar-password", esAuthDB(db, postCambiarPass, P_ALL))

	muxAdmin.HandleFunc("GET /inscritos", esAuth(handleAdminInscritos, P_ALL))
	muxAdmin.HandleFunc("GET /inscritos/", esAuth(handleAdminInscritosPag, P_ALL))
	muxAdmin.HandleFunc("GET /ver-datos/", esAuth(handleAdminVerDatos, P_ALL))

	muxAdmin.HandleFunc("GET /exportar-inscritos-xlsx", esAuth(handleExportarInscritosXlsx, P_ALL))
	muxAdmin.HandleFunc("POST /importar-inscritos-xlsx", esAuthDB(db, postImportarInscritosXlsx, P_ALL))

	// TODO: Verificar que no ocurran problemas de seguridad porque ambos servidores puedan acceder
	// 		 a la misma carpeta de recursos
	fs := http.FileServer(http.Dir(staticDir))
	fsU := http.FileServer(http.Dir(uploadedDir))
	muxPagina.Handle("GET /"+staticDir+"/", http.StripPrefix("/"+staticDir+"/", fs))
	muxAdmin.Handle("GET /"+staticDir+"/", http.StripPrefix("/"+staticDir+"/", fs))
	muxPagina.Handle("GET /"+uploadedDir+"/", http.StripPrefix("/"+uploadedDir+"/", fsU))
	muxAdmin.Handle("GET /"+uploadedDir+"/", http.StripPrefix("/"+uploadedDir+"/", fsU))

	// Golang no redirecciona a TLS automaticamente si tiene http:// en puerto no estandar
	// https://gist.github.com/d-schmidt/587ceec34ce1334a5e60
	servPagina := &http.Server{Addr: ":443", Handler: muxPagina}
	servAdmin := &http.Server{Addr: puertoServAdmin, Handler: muxAdmin}
	//go http.ListenAndServe(":80", http.HandlerFunc(redirect))

	fmt.Println("Se escucha en :443 y :80")
	correrServidores(servPagina, servAdmin)
}

/*
****************
HANDLERS
*****************
*/
func handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
	} else {
		driver := base64Captcha.NewDriverDigit(100, 240, 4, 0.7, 80)
		captcha := base64Captcha.NewCaptcha(driver, base64Captcha.DefaultMemStore)
		idCaptcha, b64s, respuestaCaptcha, err := captcha.Generate()
		if logErrorHttp(w, r, err) {
			return
		}
		if len(captchasEmitidos) < MAX_CAPTCHAS_EMITIDOS {
			captchasEmitidos = append(captchasEmitidos, CaptchaEmitido{idCaptcha, respuestaCaptcha, time.Now()})
			renderPlantillaSimple(w, "frontend", "index", map[string]any{
				"DEPARTAMENTOS": DEPARTAMENTOS,
				"SEXO":          SEXO,
				"OCUPACIONES":   OCUPACIONES,
				"EDAD":          EDAD,
				"ImagenCaptcha": template.URL(b64s),
				"IdCaptcha":     idCaptcha,
			})
		} else {
			http.NotFound(w, r)
		}
	}
}

type ResponseData struct {
	ImgB64    string `json:"ImgB64"`
	IdCaptcha string `json:"IdCaptcha"`
}

func handleRenovarCaptcha(w http.ResponseWriter, r *http.Request) {
	// Set the content type to application/json
	w.Header().Set("Content-Type", "application/json")

	driver := base64Captcha.NewDriverDigit(100, 240, 4, 0.7, 80)
	captcha := base64Captcha.NewCaptcha(driver, base64Captcha.DefaultMemStore)
	idCaptcha, b64s, respuestaCaptcha, err := captcha.Generate()
	if logErrorHttp(w, r, err) {
		return
	}
	if len(captchasEmitidos) < MAX_CAPTCHAS_EMITIDOS {
		captchasEmitidos = append(captchasEmitidos, CaptchaEmitido{idCaptcha, respuestaCaptcha, time.Now()})
		data := ResponseData{
			ImgB64:    b64s,
			IdCaptcha: idCaptcha,
		}
		// Write the JSON response
		if err := json.NewEncoder(w).Encode(data); err != nil {
			if logErrorHttp(w, r, err) {
				return
			}
		}
	} else {
		http.NotFound(w, r)
	}
}

func postEnviarInscripcion(db *badger.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		err := r.ParseMultipartForm(PARSEFORM_LIM)
		if logErrorHttp(w, r, err) {
			return
		}
		valorCaptcha := r.FormValue("captcha-input")
		idCaptcha := r.FormValue("captcha-id")

		// FILTRANDO CAPTCHAS NO VIGENTES
		var captchasValidos []CaptchaEmitido
		tieneCambios := false
		for _, capt := range captchasEmitidos {
			if capt.tiempoEmision.After(time.Now().Add(-1 * TIEMPO_VIGENCIA_CAPTCHA)) {
				captchasValidos = append(captchasValidos, capt)
			} else {
				tieneCambios = true
			}
		}
		if tieneCambios {
			captchasEmitidos = slices.Clone(captchasValidos)
		}

		// VALIDANDO QUE NO SE SUPERA EL LIMITE DE CAPTCHAS CONCURRENTES
		if len(captchasEmitidos) >= MAX_CAPTCHAS_EMITIDOS {
			if logErrorHttp(w, r, errors.New("superado el limite de captchas concurrentes")) {
				return
			}
		}
		// VALIDANDO CAPTCHA
		captchaValido := false
		idxDeCapt := -1
		for i, capt := range captchasEmitidos {
			if capt.Id == idCaptcha {
				idxDeCapt = i
				if capt.Respuesta == valorCaptcha {
					captchaValido = true
					break
				}
			}
		}

		if !captchaValido {
			// ANULANDO EN CASO QUE NO HAYA ADIVINADO EL CAPTCHA
			if idxDeCapt != -1 {
				captchasEmitidos[idxDeCapt].tiempoEmision = time.Time{}
			}
			http.NotFound(w, r)
			return
		}

		departamento, err := strconv.ParseUint(r.FormValue("departamento"), 10, 64)
		if logErrorHttp(w, r, err) {
			return
		}

		sexo, err := strconv.ParseUint(r.FormValue("sexo"), 10, 64)
		if logErrorHttp(w, r, err) {
			return
		}

		edad, err := strconv.ParseUint(r.FormValue("edad"), 10, 64)
		if logErrorHttp(w, r, err) {
			return
		}

		ocupacion, err := strconv.ParseUint(r.FormValue("ocupacion"), 10, 64)
		if logErrorHttp(w, r, err) {
			return
		}

		correoDestino := sanitizarTexto(r.FormValue("email"))

		if ValidateEmailAddress(correoDestino) != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		nombreInscrito := sanitizarTexto(r.FormValue("nombre"))

		nvoInscrito := Inscrito{
			generarUID(),
			nombreInscrito,
			sanitizarTexto(r.FormValue("institucion")),
			sanitizarTexto(r.FormValue("celular")),
			correoDestino,
			sanitizarTexto(r.FormValue("carnet")),
			uint8(departamento),
			uint8(sexo),
			uint8(edad),
			uint8(ocupacion),
		}

		mutex_inscritos.Lock()
		err = db.Update(func(txn *badger.Txn) error { /// AUMENTAR AL FINAL
			return insertarRegistro(txn, INSCRITOS, nvoInscrito)
		})
		if logErrorHttp(w, r, err) {
			mutex_inscritos.Unlock()
			return
		}

		GLOBAL_inscritos = slices.Insert(GLOBAL_inscritos, 0, hacerInscritoMas(GLOBAL_contador_inscritos, nvoInscrito))
		GLOBAL_contador_inscritos++
		mutex_inscritos.Unlock()

		/*
					auth := smtp.PlainAuth("", CORREO_REMITENTE, PASS_CORREO, SMTP_HOST)

					// Compose the message.
					// Note: The headers and body must be separated by a blank line.

					msg := fmt.Sprintf(`From: %s
			To: %s
			Subject: %s
			MIME-Version: 1.0
			Content-Type: text/html; charset=UTF-8

			%s`, CORREO_REMITENTE, correoDestino, SUBJECT1, fmt.Sprintf(BODY1, nombreInscrito))

					// Send the email.
					err = smtp.SendMail(SMTP_HOST+":587", auth, CORREO_REMITENTE, []string{correoDestino}, []byte(msg))
					if logErrorHttp(w, r, err) {
						return
					}
		*/

		w.WriteHeader(http.StatusOK)
	}
}

func handleAdminRoot(w http.ResponseWriter, r *http.Request, usuario *UsuarioMas) {
	_, autenticado := estaAutenticado(r)
	if autenticado {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
		} else {
			//renderPlantilla(w, "admin", "base", "index", map[string]any{
			//	"UsuarioLogged": usuario,
			//	"EsAdmin":       usuario.Usuario.IdPerfil == PERFIL_ADMIN,
			//})
			http.Redirect(w, r, "/inscritos", http.StatusFound)
		}
	} else {
		http.Redirect(w, r, "/login", http.StatusFound)
	}
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	_, autenticado := estaAutenticado(r)
	if !autenticado {
		http.ServeFile(w, r, "templates/admin/login.html")
	} else {
		http.NotFound(w, r)
	}
}

func handleCerrarSesion(w http.ResponseWriter, r *http.Request) {
	cookie := &http.Cookie{
		Name:     "DLPAS",
		HttpOnly: true,
		Expires:  time.Unix(0, 0), // Expiracion Inmediata
	}
	http.SetCookie(w, cookie)
	http.Redirect(w, r, "/login", http.StatusFound)
}

func handleUsuarios(w http.ResponseWriter, r *http.Request, usuario *UsuarioMas) {
	mutex_usuarios.Lock()
	us := GLOBAL_usuarios
	mutex_usuarios.Unlock()
	renderPlantilla(w, "admin", "base", "usuarios", map[string]any{ //
		"Usuarios":      us,
		"UsuarioLogged": usuario,
		"EsAdmin":       usuario.Usuario.IdPerfil == PERFIL_ADMIN,
	})
}

func handleAgregarUsuario(w http.ResponseWriter, r *http.Request, usuario *UsuarioMas) {
	renderPlantilla(w, "admin", "base", "guardar_usuario", map[string]any{ //
		"PERFIL_ADMIN":  PERFIL_ADMIN,
		"Perfiles":      PERFIL,
		"EsNuevo":       true,
		"UsuarioLogged": usuario,
		"EsAdmin":       usuario.Usuario.IdPerfil == PERFIL_ADMIN,
	})
}

func postAgregarUsuario(db *badger.DB, w http.ResponseWriter, r *http.Request, usuario *UsuarioMas) {
	err := r.ParseMultipartForm(PARSEFORM_LIM)
	if logErrorHttp(w, r, err) {
		return
	}
	idPerfil, err := strconv.Atoi(r.FormValue("perfil"))
	if logErrorHttp(w, r, err) {
		return
	}
	if idPerfil != PERFIL_ADMIN {
		passHash, err := hashPassword(r.FormValue("password"))
		if logErrorHttp(w, r, err) {
			return
		}
		nuevoUsuario := Usuario{
			uint64(time.Now().UnixMicro()),
			uint8(idPerfil),
			sanitizarTexto(r.FormValue("nombre")),
			sanitizarTexto(r.FormValue("username")),
			passHash,
		}
		mutex_usuarios.Lock()
		err = db.Update(func(txn *badger.Txn) error { /// AUMENTAR AL FINAL
			return insertarRegistro(txn, USUARIOS, nuevoUsuario)
		})
		if logErrorHttp(w, r, err) {
			mutex_usuarios.Unlock()
			return
		}
		GLOBAL_usuarios = append(GLOBAL_usuarios, hacerUsuarioMas(GLOBAL_contador_usuarios, nuevoUsuario))
		GLOBAL_contador_usuarios++
		mutex_usuarios.Unlock()
		w.WriteHeader(http.StatusOK)
	}
}

func handleUserPass(w http.ResponseWriter, r *http.Request, usuario *UsuarioMas) {
	intID, err := urlId(r.URL.Path)
	if logErrorHttp(w, r, err) {
		return
	}
	renderPlantilla(w, "admin", "base", "cambiar_pass", map[string]interface{}{
		"UsuarioLogged": usuario,
		"IdCambiar":     intID,
		"EsAdmin":       usuario.Usuario.IdPerfil == PERFIL_ADMIN,
	})
}

func postCambiarUserPass(db *badger.DB, w http.ResponseWriter, r *http.Request, usuario *UsuarioMas) {
	intID, err := urlId(r.URL.Path)
	if logErrorHttp(w, r, err) {
		return
	}
	err = r.ParseMultipartForm(PARSEFORM_LIM)
	if logErrorHttp(w, r, err) {
		return
	}
	pass, err := hashPassword(r.FormValue("password"))
	if logErrorHttp(w, r, err) {
		return
	}
	mutex_usuarios.Lock()
	var usuarioEditar *UsuarioMas
	for i := range GLOBAL_usuarios {
		if GLOBAL_usuarios[i].Id == intID {
			usuarioEditar = &GLOBAL_usuarios[i]
			break
		}
	}
	tempUsuario := usuarioEditar.Usuario
	tempUsuario.Password = pass
	err = db.Update(func(txn *badger.Txn) error { /// AUMENTAR AL FINAL
		return editarRegistro(txn, USUARIOS, tempUsuario, intID)
	})
	if logErrorHttp(w, r, err) {
		mutex_usuarios.Unlock()
		return
	}
	usuarioEditar.Usuario = tempUsuario
	mutex_usuarios.Unlock()
	w.WriteHeader(http.StatusOK)
}

func handleEliminarUsuario(db *badger.DB, w http.ResponseWriter, r *http.Request, usuario *UsuarioMas) {
	intID, err := urlId(r.URL.Path)
	if logErrorHttp(w, r, err) {
		return
	}
	if intID != 0 {
		mutex_usuarios.Lock()
		err = db.Update(func(txn *badger.Txn) error {
			return txn.Delete(crearIdBytes(USUARIOS, intID))
		})
		if logErrorHttp(w, r, err) {
			mutex_usuarios.Unlock()
			return
		}
		var pos uint32
		for i := range GLOBAL_usuarios {
			if GLOBAL_usuarios[i].Id == intID {
				pos = uint32(i)
				break
			}
		}
		GLOBAL_usuarios = append(GLOBAL_usuarios[:pos], GLOBAL_usuarios[pos+1:]...)
		mutex_usuarios.Unlock()

		w.Header().Set("Cache-Control", "no-store") // IMPORTANTE PARA EVITAR COMPORTAMIENTO NO DESEADO DEL NAVEGADOR
		http.Redirect(w, r, "/usuarios", http.StatusPermanentRedirect)
	} else {
		http.NotFound(w, r)
	}
}

func handleEditarUsuario(w http.ResponseWriter, r *http.Request, usuario *UsuarioMas) {
	intID, err := urlId(r.URL.Path)
	if logErrorHttp(w, r, err) {
		return
	}
	renderPlantilla(w, "admin", "base", "guardar_usuario", map[string]any{
		"EsNuevo":       false,
		"Id":            intID,
		"Perfiles":      PERFIL,
		"PERFIL_ADMIN":  PERFIL_ADMIN,
		"Usuario":       conseguirUsuario(intID).Usuario,
		"UsuarioLogged": usuario,
		"EsAdmin":       usuario.Usuario.IdPerfil == PERFIL_ADMIN,
	})
}

func postEditarUsuario(db *badger.DB, w http.ResponseWriter, r *http.Request, usuario *UsuarioMas) {
	intID, err := urlId(r.URL.Path)
	if logErrorHttp(w, r, err) {
		return
	}
	err = r.ParseMultipartForm(PARSEFORM_LIM)
	if logErrorHttp(w, r, err) {
		return
	}
	idPerfil, err := strconv.Atoi(r.FormValue("perfil"))
	if logErrorHttp(w, r, err) {
		return
	}
	mutex_usuarios.Lock()
	var usuarioEditar *UsuarioMas
	for i := range GLOBAL_usuarios {
		if GLOBAL_usuarios[i].Id == intID {
			usuarioEditar = &GLOBAL_usuarios[i]
			break
		}
	}
	uEd := usuarioEditar.Usuario
	if uEd.IdPerfil != PERFIL_ADMIN {
		uEd.IdPerfil = uint8(idPerfil)
	}
	uEd.NombreCompleto = sanitizarTexto(r.FormValue("nombre"))
	uEd.Username = sanitizarTexto(r.FormValue("username"))

	err = db.Update(func(txn *badger.Txn) error { /// AUMENTAR AL FINAL
		return editarRegistro(txn, USUARIOS, uEd, intID)
	})
	if logErrorHttp(w, r, err) {
		mutex_usuarios.Unlock()
		return
	}

	*usuarioEditar = hacerUsuarioMas(uint32(intID), uEd)
	mutex_usuarios.Unlock()
	w.WriteHeader(http.StatusOK)
}

func handleCambiarPass(w http.ResponseWriter, r *http.Request, usuario *UsuarioMas) {
	renderPlantilla(w, "admin", "base", "cambiar_pass", map[string]interface{}{
		"UsuarioLogged": usuario,
		"EsAdmin":       usuario.Usuario.IdPerfil == PERFIL_ADMIN,
	})
}

func postCambiarPass(db *badger.DB, w http.ResponseWriter, r *http.Request, usuario *UsuarioMas) {
	err := r.ParseMultipartForm(PARSEFORM_LIM)
	if logErrorHttp(w, r, err) {
		return
	}
	pass, err := hashPassword(r.FormValue("password"))
	if logErrorHttp(w, r, err) {
		return
	}

	mutex_usuarios.Lock()
	var usuarioEditar *UsuarioMas
	for i := range GLOBAL_usuarios {
		if GLOBAL_usuarios[i].Id == usuario.Id {
			usuarioEditar = &GLOBAL_usuarios[i]
			break
		}
	}
	tempUsuario := usuarioEditar.Usuario
	tempUsuario.Password = pass
	err = db.Update(func(txn *badger.Txn) error { /// AUMENTAR AL FINAL
		return editarRegistro(txn, USUARIOS, tempUsuario, usuario.Id)
	})
	if logErrorHttp(w, r, err) {
		mutex_usuarios.Unlock()
		return
	}
	usuarioEditar.Usuario = tempUsuario
	mutex_usuarios.Unlock()

	w.WriteHeader(http.StatusOK)
}

func handleAdminInscritos(w http.ResponseWriter, r *http.Request, usuario *UsuarioMas) {
	mutex_inscritos.Lock()
	inscritosAMostrar, enlacesEnPaginador, prevPag, nextPag := paginar(GLOBAL_inscritos, REGISTROS_POR_PAGINA_DEFAULT, 1)
	mutex_inscritos.Unlock()
	renderPlantilla(w, "admin", "base", "inscritos", map[string]any{
		"Inscritos":        inscritosAMostrar,
		"PaginaActual":     1,
		"PrevPag":          prevPag,
		"NextPag":          nextPag,
		"EnlacesPaginador": enlacesEnPaginador,
		"UsuarioLogged":    usuario,
		"EsAdmin":          usuario.Usuario.IdPerfil == PERFIL_ADMIN,
	})
}

func handleAdminInscritosPag(w http.ResponseWriter, r *http.Request, usuario *UsuarioMas) {
	var inscritosAMostrar []InscritoMas
	var enlacesEnPaginador []uint32
	var prevPag, nextPag uint32
	var query string
	intID, err := urlId(r.URL.Path)
	if logErrorHttp(w, r, err) {
		return
	}
	if intID == 0 {
		http.NotFound(w, r)
		return
	}
	if len(r.URL.RawQuery) < 3 {
		mutex_inscritos.Lock()
		inscritosAMostrar, enlacesEnPaginador, prevPag, nextPag = paginar(GLOBAL_inscritos, REGISTROS_POR_PAGINA_DEFAULT, intID)
	} else {
		query, err = url.QueryUnescape(r.URL.RawQuery[2:])
		if logErrorHttp(w, r, err) {
			return
		}
		if len(query) == 0 {
			http.NotFound(w, r)
			return
		}
		mutex_inscritos.Lock()
		var inscritosEncontrados []InscritoMas
		for i, c := range GLOBAL_inscritos {
			q := strings.ToLower(query)
			t1 := strings.ToLower(c.Inscrito.Nombre)
			t2 := strings.ToLower(c.Inscrito.Celular)
			t3 := strings.ToLower(c.Inscrito.Email)
			if strings.Contains(t1, q) ||
				strings.Contains(t2, q) ||
				strings.Contains(t3, q) {
				inscritosEncontrados = append(inscritosEncontrados, GLOBAL_inscritos[i])
			}
		}
		inscritosAMostrar, enlacesEnPaginador, prevPag, nextPag = paginar(inscritosEncontrados, REGISTROS_POR_PAGINA_DEFAULT, intID)
	}
	mutex_inscritos.Unlock()

	if len(inscritosAMostrar) == 0 && intID != 1 {
		http.NotFound(w, r)
		return
	}
	renderPlantilla(w, "admin", "base", "inscritos", map[string]any{
		"Inscritos":        inscritosAMostrar,
		"PaginaActual":     intID,
		"PrevPag":          prevPag,
		"NextPag":          nextPag,
		"Query":            r.URL.RawQuery,
		"OrigQuery":        query,
		"EnlacesPaginador": enlacesEnPaginador,
		"UsuarioLogged":    usuario,
		"EsAdmin":          usuario.Usuario.IdPerfil == PERFIL_ADMIN,
	})
}

func handleAdminVerDatos(w http.ResponseWriter, r *http.Request, usuario *UsuarioMas) {
	intID, err := urlId(r.URL.Path)
	if logErrorHttp(w, r, err) {
		return
	}

	mutex_inscritos.Lock()

	var c *InscritoMas
	for i := range GLOBAL_inscritos {
		if GLOBAL_inscritos[i].Id == intID {
			c = &GLOBAL_inscritos[i]
			break
		}
	}

	if c == nil {
		mutex_inscritos.Unlock()
		http.NotFound(w, r)
		return
	}
	mutex_inscritos.Unlock()

	renderPlantilla(w, "admin", "base", "ver_datos", map[string]any{
		"Inscrito":      c,
		"UsuarioLogged": usuario,
		"EsAdmin":       usuario.Usuario.IdPerfil == PERFIL_ADMIN,
	})
}

func handleExportarInscritosXlsx(w http.ResponseWriter, r *http.Request, usuario *UsuarioMas) {
	nombreSheet := "Inscritos"
	w.Header().Set("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
	w.Header().Set("Content-Disposition", "attachment; filename="+strings.ToLower(nombreSheet)+".xlsx")

	f := excelize.NewFile()
	f.SetSheetName(f.GetSheetName(0), nombreSheet)

	f.SetCellValue(nombreSheet, "A1", "Key")
	f.SetCellValue(nombreSheet, "B1", "Nombre")
	f.SetCellValue(nombreSheet, "C1", "Institucion")
	f.SetCellValue(nombreSheet, "D1", "Celular")
	f.SetCellValue(nombreSheet, "E1", "Email")
	f.SetCellValue(nombreSheet, "F1", "CI")
	f.SetCellValue(nombreSheet, "G1", "Departamento")
	f.SetCellValue(nombreSheet, "H1", "Sexo")
	f.SetCellValue(nombreSheet, "I1", "Edad")
	f.SetCellValue(nombreSheet, "J1", "Ocupacion")

	mutex_inscritos.Lock()
	for i, c := range GLOBAL_inscritos {
		f.SetCellValue(nombreSheet, fmt.Sprintf("A%d", i+2), strconv.FormatUint(c.Inscrito.Key, 10))
		f.SetCellValue(nombreSheet, fmt.Sprintf("B%d", i+2), c.Inscrito.Nombre)
		f.SetCellValue(nombreSheet, fmt.Sprintf("C%d", i+2), c.Inscrito.Institucion)
		f.SetCellValue(nombreSheet, fmt.Sprintf("D%d", i+2), c.Inscrito.Celular)
		f.SetCellValue(nombreSheet, fmt.Sprintf("E%d", i+2), c.Inscrito.Email)
		f.SetCellValue(nombreSheet, fmt.Sprintf("F%d", i+2), c.Inscrito.CI)
		f.SetCellValue(nombreSheet, fmt.Sprintf("G%d", i+2), c.DepartamentoStr)
		f.SetCellValue(nombreSheet, fmt.Sprintf("H%d", i+2), c.SexoStr)
		f.SetCellValue(nombreSheet, fmt.Sprintf("I%d", i+2), c.EdadStr)
		f.SetCellValue(nombreSheet, fmt.Sprintf("J%d", i+2), c.OcupacionStr)
	}
	err := f.AddTable(nombreSheet, &excelize.Table{
		Range:     fmt.Sprintf("A1:J%d", len(GLOBAL_inscritos)+1),
		StyleName: "TableStyleMedium2",
	})
	if logErrorHttp(w, r, err) {
		mutex_inscritos.Unlock()
		return
	}
	mutex_inscritos.Unlock()
	// NOTA: Agregar Autofit cuando este disponible
	// https://github.com/qax-os/excelize/issues/92
	buf, err := f.WriteToBuffer()
	if logErrorHttp(w, r, err) {
		return
	}
	if logErrorHttp(w, r, f.Close()) {
		return
	}
	w.Write(buf.Bytes())
}

func postImportarInscritosXlsx(db *badger.DB, w http.ResponseWriter, r *http.Request, usuario *UsuarioMas) {
	err := r.ParseMultipartForm(PARSEFORM_LIM)
	if logErrorHttp(w, r, err) {
		return
	}
	multipartFormData := r.MultipartForm
	if len(multipartFormData.File["file"]) > 1 {
		if logErrorHttp(w, r, errors.New("error, no se acepta mas de 1 archivo")) {
			return
		}
	}
	var inscritos []Inscrito

	uploadedFile, err := multipartFormData.File["file"][0].Open() //uploadedFile
	if logErrorHttp(w, r, err) {
		return
	}
	f, err := excelize.OpenReader(uploadedFile, excelize.Options{
		RawCellValue: true,
	})
	if logErrorHttp(w, r, err) {
		return
	}

	rowsRaw, err := f.GetRows("Inscritos", excelize.Options{
		RawCellValue: true,
	})
	if logErrorHttp(w, r, err) {
		return
	}

	rows := normalizarRows(rowsRaw, 10)

	for i := 1; i < len(rows); i++ {
		key, err := strconv.ParseUint(rows[i][0], 10, 64)
		if logErrorHttp(w, r, err) {
			return
		}

		departamento, exists := CONTR_DEPARTAMENTOS[rows[i][6]]
		if !exists {
			if logErrorHttp(w, r, errors.New("error al parsear departamentos")) {
				return
			}
		}

		sexo, exists := CONTR_SEXO[rows[i][7]]
		if !exists {
			if logErrorHttp(w, r, errors.New("error al parsear sexo")) {
				return
			}
		}

		edad, exists := CONTR_EDAD[rows[i][8]]
		if !exists {
			if logErrorHttp(w, r, errors.New("error al parsear edad")) {
				return
			}
		}

		ocupacion, exists := CONTR_OCUPACIONES[rows[i][9]]
		if !exists {
			if logErrorHttp(w, r, errors.New("error al parsear ocupacion")) {
				return
			}
		}
		inscritos = append(inscritos, Inscrito{
			key,
			rows[i][1], // NOMBRE
			rows[i][2], // INST
			rows[i][3], // CELULAR
			rows[i][4], // EMAIL
			rows[i][5], // CI
			departamento,
			sexo,
			edad,
			ocupacion,
		})
	}

	mutex_inscritos.Lock()
	err = reemplazarTabla(db, INSCRITOS, inscritos)
	if logErrorHttp(w, r, err) {
		mutex_inscritos.Unlock()
		return
	}
	GLOBAL_contador_inscritos = uint32(len(inscritos))
	GLOBAL_inscritos = nil
	GLOBAL_inscritos = make([]InscritoMas, len(inscritos))

	for i, c := range inscritos {
		GLOBAL_inscritos[i] = hacerInscritoMas(uint32(i), c)
	}
	// AQUI ORDENAR POR FECHA
	slices.SortFunc(GLOBAL_inscritos, func(a, b InscritoMas) int {
		return cmp.Compare(b.Inscrito.Key, a.Inscrito.Key)
	})
	mutex_inscritos.Unlock()

	w.WriteHeader(http.StatusOK)
}

/*****************
HERRAMIENTAS
******************/

func editarRegistro(txn *badger.Txn, idTabla uint8, data any, idData uint32) error {
	keyCont := make([]byte, 1)
	keyCont[0] = 0b10000000 | idTabla // Conseguir el contador de la tabla
	var dataBytes bytes.Buffer
	enc := gob.NewEncoder(&dataBytes)
	err := enc.Encode(data)
	if err != nil {
		fmt.Println("Error al serializar informacion para tabla: ", TABLAS[idTabla])
		return err
	}
	err = txn.Set(crearIdBytes(idTabla, idData), dataBytes.Bytes())
	if err != nil {
		fmt.Println("Error al cargar data a la tabla: ", TABLAS[idTabla])
		return err
	}
	return nil
}

func crearIdBytes(idTabla uint8, idData uint32) []byte {
	idDataB := IntToBytes(idData)
	keyRegistro := make([]byte, 5)
	keyRegistro[0] = idTabla
	keyRegistro[1] = idDataB[0]
	keyRegistro[2] = idDataB[1]
	keyRegistro[3] = idDataB[2]
	keyRegistro[4] = idDataB[3]
	return keyRegistro
}

func urlId(path string) (uint32, error) {
	parts := strings.Split(path, "/")
	if len(parts) > 3 {
		return 0, errors.New("URL no cumple formato")
	}
	intID, err := strconv.Atoi(parts[len(parts)-1])
	if err != nil || intID < 0 {
		fmt.Println("Error al interpretar ID: ", err)
		return 0, errors.New("URL no cumple formato")
	}
	return uint32(intID), nil
}

func hacerUsuarioMas(id uint32, usuario Usuario) UsuarioMas {
	return UsuarioMas{
		id,
		usuario,
		PERFIL[usuario.IdPerfil],
	}
}

func sanitizarTexto(input string) string {
	// Replace <, >, & with a whitespace
	replacements := map[string]string{
		"<": " ",
		">": " ",
		"&": " ",
		`"`: " ",
		`'`: " ",
	}

	// Iterate over the map and perform replacements
	for old, new := range replacements {
		input = strings.ReplaceAll(input, old, new)
	}

	return strings.TrimSpace(input)
}

func renderPlantilla(w http.ResponseWriter, carpetaBase string, nombreBase string, nombrePlantilla string, data any) {
	if len(carpetaBase) == 0 {
		log.Fatal("Nombre de carpeta base no puede estar vacio")
	}
	if FileExists("templates/"+carpetaBase+"/"+nombreBase+".html") && FileExists("templates/"+carpetaBase+"/"+nombrePlantilla+".html") {
		plantillas, err := template.ParseFiles("templates/"+carpetaBase+"/"+nombreBase+".html", "templates/"+carpetaBase+"/"+nombrePlantilla+".html")
		if err != nil {
			fmt.Println("Error al parsear plantillas: ", nombreBase, ".html y ", nombrePlantilla, ".html\n Error: ", err)
		}
		err = plantillas.ExecuteTemplate(w, "base", data)
		if err != nil {
			fmt.Println("Error renderizando Plantilla: ", err)
		}
	} else {
		fmt.Println("Error renderizando plantillas: ", nombreBase, ".html y ", nombrePlantilla, ".html... No existe")
	}
}

func renderPlantillaSimple(w http.ResponseWriter, carpetaBase string, nombrePlantilla string, data any) {
	if len(carpetaBase) == 0 {
		log.Fatal("Nombre de carpeta base no puede estar vacio")
	}
	if FileExists("templates/" + carpetaBase + "/" + nombrePlantilla + ".html") {
		plantillas, err := template.ParseFiles("templates/" + carpetaBase + "/" + nombrePlantilla + ".html")
		if err != nil {
			fmt.Println("Error al parsear plantillas: ", nombrePlantilla, ".html\n Error: ", err)
		}
		err = plantillas.ExecuteTemplate(w, nombrePlantilla, data)
		if err != nil {
			fmt.Println("Error renderizando Plantilla: ", err)
		}
	} else {
		fmt.Println("Error renderizando plantillas: ", nombrePlantilla, ".html... No existe")
	}
}

// FileExists checks if the specified file exists.
func FileExists(filename string) bool {
	if len(filename) == 0 {
		return false
	}
	_, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return err == nil
}

func postCredenciales(db *badger.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, err := verificarCredenciales(r)
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
		} else {
			// Si uso 30 bytes entonces saldra un string base64 de 40 bytes
			randomBytes := make([]byte, 30)
			rand.Read(randomBytes)
			sessionID := base64.URLEncoding.EncodeToString(randomBytes)
			mutex_sesiones.Lock()
			err = guardarSesion(db, sessionID, user.Id)
			if logErrorHttp(w, r, err) {
				mutex_sesiones.Unlock()
				return
			}
			GLOBAL_sesiones = append(GLOBAL_sesiones, Sesion{
				IdUsuario: user.Id,
				Valor:     sessionID,
			})
			mutex_sesiones.Unlock()
			http.SetCookie(w, &http.Cookie{
				Name:   "DLPAS",
				Value:  sessionID,
				MaxAge: 5184000,
			})
			http.Redirect(w, r, "/", http.StatusFound)
		}
	}
}

func logErrorHttp(w http.ResponseWriter, r *http.Request, err error) bool {
	if err != nil {
		fmt.Println("Error al procesar: ", r.URL.Path)
		fmt.Println("El error es: ", err)
		http.NotFound(w, r)
	}
	return err != nil
}

func guardarSesion(db *badger.DB, sessionID string, idUsuario uint32) error {
	if len(sessionID) != 40 {
		return errors.New("error con sessionID, deberia ser 40 caracteres base64 de largo")
	}
	err := db.Update(func(txn *badger.Txn) error { /// AUMENTAR AL FINAL
		sessionKey := make([]byte, 41)
		sessionKey[0] = SESIONES
		for i := range sessionID {
			sessionKey[i+1] = sessionID[i]
		}
		e := badger.NewEntry(sessionKey, IntToBytes(idUsuario)).WithTTL(1440 * time.Hour)
		err := txn.SetEntry(e)
		if err != nil {
			return err
		}
		return nil
	})
	return err
}

func verificarCredenciales(r *http.Request) (UsuarioMas, error) {
	r.ParseForm()
	username := r.Form["username"][0]
	password := r.Form["password"][0]
	passwordHashed, err := hashPassword(password)
	if err != nil {
		fmt.Println("Error al hashear password: ", err)
		return UsuarioMas{}, err
	}
	var usuarioEncontrado UsuarioMas
	var encontrado bool
	mutex_usuarios.Lock()
	for _, u := range GLOBAL_usuarios {
		if u.Usuario.Password == passwordHashed && u.Usuario.Username == username {
			usuarioEncontrado = u
			encontrado = true
			break
		}
	}
	mutex_usuarios.Unlock()
	if !encontrado {
		err = errors.New("Usuario no encontrado")
	}
	return usuarioEncontrado, err
}

func hashPassword(password string) (string, error) {
	passwordBytes := []byte(password)
	sha := sha512.New()
	_, err := sha.Write(passwordBytes)
	if err != nil {
		return "", err
	}
	hashedPassword := sha.Sum(nil)
	hashedPasswordString := hex.EncodeToString(hashedPassword)
	return hashedPasswordString, nil
}

func estaAutenticado(r *http.Request) (uint32, bool) {
	cookie, err := r.Cookie("DLPAS")
	if err != nil || len(cookie.Value) != 40 {
		return 0, false
	}
	var salida uint32
	encontrado := false
	mutex_sesiones.Lock()
	for i := range GLOBAL_sesiones {
		if cookie.Value == GLOBAL_sesiones[i].Valor {
			salida = GLOBAL_sesiones[i].IdUsuario
			encontrado = true
			break
		}
	}
	mutex_sesiones.Unlock()
	return salida, encontrado
}

func esAuth(fp func(http.ResponseWriter, *http.Request, *UsuarioMas), perfiles []uint8) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		idUserLogged, autenticado := estaAutenticado(r)
		if autenticado {
			u := conseguirUsuario(idUserLogged)
			esPermitido := false
			for _, p := range perfiles {
				esPermitido = esPermitido || u.Usuario.IdPerfil == p
			}
			if esPermitido {
				fp(w, r, u)
			} else {
				http.NotFound(w, r)
			}
		} else {
			http.Redirect(w, r, "/login", http.StatusFound)
		}
	}
}

func esAuthDB(db *badger.DB, fp func(*badger.DB, http.ResponseWriter, *http.Request, *UsuarioMas), perfiles []uint8) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		idUserLogged, autenticado := estaAutenticado(r)
		if autenticado {
			u := conseguirUsuario(idUserLogged)
			esPermitido := false
			for _, p := range perfiles {
				esPermitido = esPermitido || u.Usuario.IdPerfil == p
			}
			if esPermitido {
				fp(db, w, r, u)
			} else {
				http.NotFound(w, r)
			}
		} else {
			http.Redirect(w, r, "/login", http.StatusFound)
		}
	}
}

func conseguirUsuario(idUser uint32) *UsuarioMas {
	var usuarioLogged *UsuarioMas
	mutex_usuarios.Lock()
	for i := range GLOBAL_usuarios {
		if GLOBAL_usuarios[i].Id == idUser {
			usuarioLogged = &GLOBAL_usuarios[i]
			break
		}
	}
	mutex_usuarios.Unlock()
	return usuarioLogged
}

func redirect(w http.ResponseWriter, r *http.Request) {
	// remove/add not default ports from req.Host
	target := "https://" + r.Host + r.URL.Path
	if len(r.URL.RawQuery) > 0 {
		target += "?" + r.URL.RawQuery
	}
	log.Printf("redirect to: %s", target)
	http.Redirect(w, r, target, http.StatusPermanentRedirect)
}

func correrServidores(serverOne *http.Server, serverTwo *http.Server) {
	wg := sync.WaitGroup{}
	wg.Add(2)
	go func() {
		defer wg.Done()
		err := serverOne.ListenAndServe()
		if errors.Is(err, http.ErrServerClosed) {
			fmt.Printf("Servidor 1 cerrado\n")
		} else if err != nil {
			fmt.Printf("error listening for server one: %s\n", err)
		}
	}()
	go func() {
		defer wg.Done()
		err := serverTwo.ListenAndServe()
		if errors.Is(err, http.ErrServerClosed) {
			fmt.Printf("Servidor 2 cerrado\n")
		} else if err != nil {
			fmt.Printf("error listening for server two: %s\n", err)
		}
	}()
	wg.Wait()
	fmt.Println("El servidor se apagara...")
}

func insertarRegistro(txn *badger.Txn, idTabla uint8, data any) error {
	keyCont := make([]byte, 1)
	keyCont[0] = 0b10000000 | idTabla // Conseguir el contador de la tabla
	cont, err := txn.Get(keyCont)
	if err != nil {
		fmt.Println("Error al conseguir el contador de tabla: ", TABLAS[idTabla])
		return err
	}
	var valorContador []byte
	err = cont.Value(func(val []byte) error {
		valorContador = append([]byte{}, val...)
		return nil
	})
	if err != nil {
		fmt.Println("Error al conseguir contador item tabla: ", TABLAS[idTabla])
		return err
	}
	var dataBytes bytes.Buffer
	enc := gob.NewEncoder(&dataBytes)
	err = enc.Encode(data)
	if err != nil {
		fmt.Println("Error al serializar informacion para tabla: ", TABLAS[idTabla])
		return err
	}
	keyNvoRegistro := make([]byte, 5)
	keyNvoRegistro[0] = idTabla
	keyNvoRegistro[1] = valorContador[0]
	keyNvoRegistro[2] = valorContador[1]
	keyNvoRegistro[3] = valorContador[2]
	keyNvoRegistro[4] = valorContador[3]
	err = txn.Set(keyNvoRegistro, dataBytes.Bytes())
	if err != nil {
		fmt.Println("Error al cargar data a la tabla: ", TABLAS[idTabla])
		return err
	}
	dataId := uint32(valorContador[0])<<24 | uint32(valorContador[1])<<16 | uint32(valorContador[2])<<8 | uint32(valorContador[3])
	err = txn.Set(keyCont, IntToBytes(dataId+1))
	if err != nil {
		fmt.Println("Error al aumentar contador de tabla: ", TABLAS[idTabla], " a nuevo valor")
		return err
	}
	return nil
}

func iniciarTablasGlobales(db *badger.DB) error {
	var idsTempUsuarios []uint32
	var tempUsuarios []Usuario
	var idsTempInscritos []uint32
	var tempInscritos []Inscrito

	err := db.View(func(txn *badger.Txn) error {
		var err error
		idsTempUsuarios, tempUsuarios, err = conseguirTodos[Usuario](txn, USUARIOS)
		if err != nil {
			return err
		}
		GLOBAL_contador_usuarios, err = conseguirContador[Usuario](txn, USUARIOS)
		if err != nil {
			return err
		}
		idsTempInscritos, tempInscritos, err = conseguirTodos[Inscrito](txn, INSCRITOS)
		if err != nil {
			return err
		}
		GLOBAL_contador_inscritos, err = conseguirContador[Inscrito](txn, INSCRITOS)
		if err != nil {
			return err
		}
		GLOBAL_sesiones, err = conseguirSesiones(txn)
		return err
	})
	if err != nil {
		return err
	}
	GLOBAL_usuarios = make([]UsuarioMas, len(tempUsuarios))
	for i := range tempUsuarios {
		GLOBAL_usuarios[i] = hacerUsuarioMas(idsTempUsuarios[i], tempUsuarios[i])
	}
	GLOBAL_inscritos = make([]InscritoMas, len(tempInscritos))
	for i := range tempInscritos {
		GLOBAL_inscritos[i] = hacerInscritoMas(idsTempInscritos[i], tempInscritos[i])
	}
	// AQUI ORDENAR
	slices.SortFunc(GLOBAL_inscritos, func(a, b InscritoMas) int {
		return cmp.Compare(b.Inscrito.Key, a.Inscrito.Key)
	})
	return nil
}

func conseguirSesiones(txn *badger.Txn) ([]Sesion, error) {
	it := txn.NewIterator(badger.DefaultIteratorOptions)
	defer it.Close()
	prefix := make([]byte, 1)
	prefix[0] = SESIONES

	var sesiones []Sesion
	for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
		item := it.Item()
		k := item.Key()
		valor := k[1:]
		bytesUsuario, err := txn.Get(k)
		if err != nil {
			return nil, err
		}
		var valCopy []byte
		err = bytesUsuario.Value(func(val []byte) error {
			valCopy = append([]byte{}, val...)
			return nil
		})
		if err != nil {
			return nil, err
		}
		idUsuario, err := BytesToInt(valCopy)
		if err != nil {
			return nil, err
		}
		sesiones = append(sesiones, Sesion{
			IdUsuario: idUsuario,
			Valor:     string(valor),
		})
	}
	return sesiones, nil
}

func crearRegistrosIniciales(db *badger.DB) {
	err := iniciarTablaGrande(db, USUARIOS, USUARIOS_0)
	if err != nil {
		log.Fatal("Error al cargar valores iniciales: ", err)
	}

	err = iniciarTablaGrande(db, INSCRITOS, []Inscrito{})
	if err != nil {
		log.Fatal("Error al cargar valores iniciales: ", err)
	}
}

func iniciarTablaGrande[T Tabla](db *badger.DB, idTabla uint8, dataArray []T) error {
	// PRIMERO VERIFICAR SI EXISTEN VALORES REGISTRADOS
	keyCont := make([]byte, 1)
	keyCont[0] = 0b10000000 | idTabla

	txn := db.NewTransaction(true)
	defer txn.Discard()
	item, err := txn.Get(keyCont)

	if err == badger.ErrKeyNotFound {
		fmt.Println("No se encontro tabla: ", TABLAS[idTabla], " se lo pondra los valores iniciales...")
		err := insertarVariosRegistrosZeroBIG(db, idTabla, dataArray)
		if err != nil {
			fmt.Println("Error al iniciar tabla: ", TABLAS[idTabla])
			return err
		}
		fmt.Println("Se cargaron ", len(dataArray), " registros de ", TABLAS[idTabla])
		return nil
	} else if err != nil {
		fmt.Println("Error fatal al intentar conseguir conteo de tabla: ", TABLAS[idTabla])
		return err
	} else {
		// AQUI TODO NORMAL
		var valCopy []byte
		err = item.Value(func(val []byte) error {
			valCopy = slices.Clone(val)
			return nil
		})
		if err != nil {
			fmt.Println("Error al conseguir item")
			return err
		}
		conteo, err := BytesToInt(valCopy)
		if err != nil {
			return err
		}
		fmt.Println("El conteo de registros para tabla: ", TABLAS[idTabla], " es de: ", conteo)
		return nil
	}
}

func insertarVariosRegistrosZeroBIG[T Tabla](db *badger.DB, idTabla uint8, data []T) error {
	txn := db.NewTransaction(true)
	defer txn.Discard()
	wb := db.NewWriteBatch()
	defer wb.Cancel()
	keyCont := make([]byte, 1)
	keyCont[0] = 0b10000000 | idTabla // Conseguir el contador de la tabla
	valorContador := make([]byte, 4)
	var err error
	for _, d := range data {
		var dataBytes bytes.Buffer
		enc := gob.NewEncoder(&dataBytes)
		err = enc.Encode(d)
		if err != nil {
			fmt.Println("Error al serializar informacion para tabla: ", TABLAS[idTabla])
			return err
		}
		keyNvoRegistro := make([]byte, 5)
		keyNvoRegistro[0] = idTabla
		keyNvoRegistro[1] = valorContador[0]
		keyNvoRegistro[2] = valorContador[1]
		keyNvoRegistro[3] = valorContador[2]
		keyNvoRegistro[4] = valorContador[3]
		err = wb.Set(keyNvoRegistro, dataBytes.Bytes())
		if err != nil {
			fmt.Println("Error al cargar data a la tabla: ", TABLAS[idTabla])
			return err
		}
		tempId := uint32(valorContador[0])<<24 | uint32(valorContador[1])<<16 | uint32(valorContador[2])<<8 | uint32(valorContador[3])
		valorContador = IntToBytes(tempId + 1)
	}

	err = wb.Set(keyCont, valorContador)
	if err != nil {
		fmt.Println("Error al aumentar contador de tabla: ", TABLAS[idTabla], " a nuevo valor")
		return err
	}
	return wb.Flush()
}

func conseguirTodos[T Tabla](txn *badger.Txn, idTabla uint8) ([]uint32, []T, error) {
	opts := badger.DefaultIteratorOptions
	opts.PrefetchValues = false
	it := txn.NewIterator(opts)
	defer it.Close()
	var dataArray []T
	var ids []uint32
	prefix := make([]byte, 1)
	// Solo podra tenerse 255 tablas
	prefix[0] = idTabla
	for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
		item := it.Item()
		k := item.Key()
		itemId := uint32(k[1])<<24 | uint32(k[2])<<16 | uint32(k[3])<<8 | uint32(k[4])
		ids = append(ids, itemId)
		err := item.Value(func(val []byte) error {
			var data T
			z := bytes.NewBuffer(val)
			dec := gob.NewDecoder(z)
			err := dec.Decode(&data)
			if err != nil {
				fmt.Println("decode error: ", err)
				return err
			}
			dataArray = append(dataArray, data)
			return nil
		})
		if err != nil {
			return nil, nil, err
		}
	}
	return ids, dataArray, nil
}

func conseguirContador[T Tabla](txn *badger.Txn, idTabla uint8) (uint32, error) {
	keyCont := make([]byte, 1)
	keyCont[0] = 0b10000000 | idTabla // Conseguir el contador de la tabla
	cont, err := txn.Get(keyCont)
	if err != nil {
		fmt.Println("Error al conseguir el contador de tabla: ", TABLAS[idTabla])
		return 0, err
	}
	var valorContador []byte
	err = cont.Value(func(val []byte) error {
		valorContador = append([]byte{}, val...)
		return nil
	})
	if err != nil {
		fmt.Println("Error al conseguir contador item tabla: ", TABLAS[idTabla])
		return 0, err
	}
	dataId := uint32(valorContador[0])<<24 | uint32(valorContador[1])<<16 | uint32(valorContador[2])<<8 | uint32(valorContador[3])
	return dataId, nil
}

func BytesToInt(k []byte) (uint32, error) {
	if len(k) != 4 {
		return 0, errors.New("error datos deben ser solo de 4 bytes")
	}
	return uint32(k[0])<<24 | uint32(k[1])<<16 | uint32(k[2])<<8 | uint32(k[3]), nil
}

func IntToBytes(dataInt uint32) []byte {
	dataBytes := make([]byte, 4)
	dataBytes[0] = byte((dataInt >> 24) & 0x000000FF)
	dataBytes[1] = byte((dataInt >> 16) & 0x000000FF)
	dataBytes[2] = byte((dataInt >> 8) & 0x000000FF)
	dataBytes[3] = byte((dataInt) & 0x000000FF)
	return dataBytes
}

func reverseMap(m map[uint8]string) map[string]uint8 {
	n := make(map[string]uint8, len(m))
	for k, v := range m {
		n[v] = k
	}
	return n
}

func generarUID() uint64 {
	return uint64(time.Now().UnixNano())
}

func paginar[T TablaMas](tabla []T, registrosPorPag uint32, nro_pagina uint32) ([]T, []uint32, uint32, uint32) {
	idxPag := nro_pagina - 1
	NRO_REGISTROS := uint32(len(tabla))
	totalPags := NRO_REGISTROS / registrosPorPag
	sobra := NRO_REGISTROS % registrosPorPag
	if sobra != 0 {
		totalPags++
	}
	if totalPags < nro_pagina {
		return nil, nil, 0, 0
	}
	offset := registrosPorPag * idxPag

	var enlacesEnPaginador []uint32

	if totalPags < 8 {
		enlacesEnPaginador = make([]uint32, totalPags)
		for i := range enlacesEnPaginador {
			enlacesEnPaginador[i] = uint32(i + 1)
		}
	}
	if totalPags > 7 {
		if nro_pagina == 1 || nro_pagina == 2 {
			enlacesEnPaginador = []uint32{1, 2, 3, 0, totalPags}
		}
		if nro_pagina == 3 {
			enlacesEnPaginador = []uint32{1, 2, 3, 4, 0, totalPags}
		}
		if nro_pagina == 4 {
			enlacesEnPaginador = []uint32{1, 2, 3, 4, 5, 0, totalPags}
		}
		if nro_pagina > 4 && nro_pagina < totalPags-3 {
			enlacesEnPaginador = []uint32{1, 0, nro_pagina - 1, nro_pagina, nro_pagina + 1, 0, totalPags}
		}
		if nro_pagina == totalPags-3 {
			enlacesEnPaginador = []uint32{1, 0, totalPags - 4, totalPags - 3, totalPags - 2, totalPags - 1, totalPags}
		}
		if nro_pagina == totalPags-2 {
			enlacesEnPaginador = []uint32{1, 0, totalPags - 3, totalPags - 2, totalPags - 1, totalPags}
		}
		if nro_pagina == totalPags-1 || nro_pagina == totalPags {
			enlacesEnPaginador = []uint32{1, 0, totalPags - 2, totalPags - 1, totalPags}
		}
	}

	if nro_pagina == totalPags {
		return tabla[offset:], enlacesEnPaginador, totalPags - 1, 0
	}

	return tabla[offset : registrosPorPag+offset], enlacesEnPaginador, nro_pagina - 1, nro_pagina + 1
}

func hacerInscritoMas(id uint32, ins Inscrito) InscritoMas {
	return InscritoMas{
		id,
		ins,
		DEPARTAMENTOS[ins.Departamento],
		SEXO[ins.Sexo],
		EDAD[ins.Edad],
		OCUPACIONES[ins.Ocupacion],
	}
}

func ValidateEmailAddress(email string) error {
	// 1. Syntax Validation
	_, err := mail.ParseAddress(email)
	if err != nil {
		return fmt.Errorf("email syntax is invalid: %w", err)
	}

	// 2. Domain Validation (MX Records)
	parts := strings.Split(email, "@")
	domain := parts[1]

	mxRecords, err := net.LookupMX(domain)
	if err != nil {
		if dnsErr, ok := err.(*net.DNSError); ok && dnsErr.IsNotFound {
			return fmt.Errorf("domain does not exist: %w", err)
		}
		return fmt.Errorf("could not look up MX records: %w", err)
	}

	if len(mxRecords) == 0 {
		return fmt.Errorf("no MX records found for domain")
	}

	return nil
}

func normalizarRows(rowsRaw [][]string, w int) [][]string {
	rows := make([][]string, len(rowsRaw))
	for i, r := range rowsRaw {
		rows[i] = make([]string, w)
		copy(rows[i], r)
	}
	return rows
}

func reemplazarTabla[T Tabla](db *badger.DB, idTabla uint8, data []T) error {
	//start := time.Now()
	err := borrarTablaBIG(db, idTabla)
	if err != nil {
		return err
	}
	//duration := time.Since(start)
	//fmt.Println("El tiempo que dura la operacion es: ", duration)
	//start := time.Now()
	err = insertarVariosRegistrosBIG(db, idTabla, data)
	if err != nil {
		return err
	}
	//duration := time.Since(start)
	//fmt.Println("El tiempo que dura la operacion es: ", duration)
	return nil
}

func borrarTablaBIG(db *badger.DB, idTabla uint8) error {
	txn := db.NewTransaction(true)
	defer txn.Discard()
	wb := db.NewWriteBatch()
	defer wb.Cancel()
	keyCont := make([]byte, 1)
	valorCero := make([]byte, 4)
	keyCont[0] = 0b10000000 | idTabla
	err := wb.Set(keyCont, valorCero)
	if err != nil {
		fmt.Println("Error al setear contador de tabla: ", TABLAS[idTabla], " a 0")
		return err
	}
	prefix := make([]byte, 1)
	prefix[0] = idTabla

	it := txn.NewIterator(badger.DefaultIteratorOptions)
	defer it.Close()

	for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
		keyTemp := it.Item().KeyCopy(nil)
		err := wb.Delete(keyTemp)
		if err == badger.ErrTxnTooBig {
			break
		} else if err != nil {
			fmt.Println("Error al cargar data a la tabla: ", TABLAS[idTabla])
			return err
		}
	}

	return wb.Flush()
}

func insertarVariosRegistrosBIG[T Tabla](db *badger.DB, idTabla uint8, data []T) error {
	txn := db.NewTransaction(true)
	defer txn.Discard()
	wb := db.NewWriteBatch()
	defer wb.Cancel()
	keyCont := make([]byte, 1)
	keyCont[0] = 0b10000000 | idTabla // Conseguir el contador de la tabla
	cont, err := txn.Get(keyCont)
	if err != nil {
		fmt.Println("Error al conseguir el contador de tabla: ", TABLAS[idTabla])
		return err
	}
	var valorContador []byte
	err = cont.Value(func(val []byte) error {
		valorContador = append([]byte{}, val...)
		return nil
	})
	if err != nil {
		fmt.Println("Error al conseguir contador item tabla: ", TABLAS[idTabla])
		return err
	}

	for _, d := range data {
		var dataBytes bytes.Buffer
		enc := gob.NewEncoder(&dataBytes)
		err = enc.Encode(d)
		if err != nil {
			fmt.Println("Error al serializar informacion para tabla: ", TABLAS[idTabla])
			return err
		}
		keyNvoRegistro := make([]byte, 5)
		keyNvoRegistro[0] = idTabla
		keyNvoRegistro[1] = valorContador[0]
		keyNvoRegistro[2] = valorContador[1]
		keyNvoRegistro[3] = valorContador[2]
		keyNvoRegistro[4] = valorContador[3]
		err = wb.Set(keyNvoRegistro, dataBytes.Bytes())
		if err != nil {
			fmt.Println("Error al cargar data a la tabla: ", TABLAS[idTabla])
			return err
		}
		tempId := uint32(valorContador[0])<<24 | uint32(valorContador[1])<<16 | uint32(valorContador[2])<<8 | uint32(valorContador[3])
		valorContador = IntToBytes(tempId + 1)
	}

	err = wb.Set(keyCont, valorContador)
	if err != nil {
		fmt.Println("Error al aumentar contador de tabla: ", TABLAS[idTabla], " a nuevo valor")
		return err
	}
	return wb.Flush()
}
