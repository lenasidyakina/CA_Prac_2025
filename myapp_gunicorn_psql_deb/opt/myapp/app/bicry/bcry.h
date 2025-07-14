#ifndef _B_CRY_H_
#define _B_CRY_H_

#ifdef UNIX
#ifdef __MACOS__
#define DECL __attribute__((visibility("default")))
#define DECL8(abc) __attribute__((visibility("default"))) abc
#else
#define DECL
#define DECL8(a) a
#endif
#else //UNIX
#ifdef __MACOS__
#define DECL __stdcall __declspec(dllexport)
#define DECL8(abc) __declspec(dllexport) abc __stdcall 
#else
#define DECL __stdcall
#define DECL8(a) a __stdcall
#endif
#endif

#define cPKCS    32
#define cVPNKEY  16
#define cFPSU    8
#define cTMDRV   4
#define cDSCH    2
#define cGKUZ    1


//Для ГОСТ-2001, ключ 256 бит, параметры хеш 34.11-94
#define	PARAM_KSB_S			53  //'5' - id-GostR3410-2001-CryptoPro-B-ParamSet (deprecated)
#define	PARAM_A				65	//'A' - {0x07, 0x2A, 0x85, 0x03, 0x02, 0x02, 0x23, 0x01}  1.2.643.2.2.35.1  id-GostR3410-2001-CryptoPro-A-ParamSet
#define	PARAM_B				66  //'B' - {0x07, 0x2A, 0x85, 0x03, 0x02, 0x02, 0x23, 0x02}  1.2.643.2.2.35.2  id-GostR3410-2001-CryptoPro-B-ParamSet
#define	PARAM_C				67  //'C' - {0x07, 0x2A, 0x85, 0x03, 0x02, 0x02, 0x23, 0x03}  1.2.643.2.2.35.3  id-GostR3410-2001-CryptoPro-C-ParamSet
#define	PARAM_XchA			88  //'X' - {0x07, 0x2A, 0x85, 0x03, 0x02, 0x02, 0x24, 0x00}  1.2.643.2.2.36.0  id-GostR3410-2001-CryptoPro-XchA-ParamSet
#define	PARAM_XchB			89  //'Y' - {0x07, 0x2A, 0x85, 0x03, 0x02, 0x02, 0x24, 0x01}  1.2.643.2.2.36.1  id-GostR3410-2001-CryptoPro-XchB-ParamSet
#define	PARAM_HASH			72  //'H'

//Для ГОСТ-2012, ключ 256 бит, параметры хеш 34.11-2012
#define	PARAM_A_12			97	//'a' - {0x07, 0x2A, 0x85, 0x03, 0x02, 0x02, 0x23, 0x01}  1.2.643.2.2.35.1  id-GostR3410-2001-CryptoPro-A-ParamSet
#define	PARAM_B_12			98  //'b' - {0x07, 0x2A, 0x85, 0x03, 0x02, 0x02, 0x23, 0x02}  1.2.643.2.2.35.2  id-GostR3410-2001-CryptoPro-B-ParamSet
#define	PARAM_C_12			99  //'c' - {0x07, 0x2A, 0x85, 0x03, 0x02, 0x02, 0x23, 0x03}  1.2.643.2.2.35.3  id-GostR3410-2001-CryptoPro-C-ParamSet
#define	PARAM_XchA_12		120 //'x' - {0x07, 0x2A, 0x85, 0x03, 0x02, 0x02, 0x24, 0x00}  1.2.643.2.2.36.0  id-GostR3410-2001-CryptoPro-XchA-ParamSet
#define	PARAM_XchB_12		121 //'y' - {0x07, 0x2A, 0x85, 0x03, 0x02, 0x02, 0x24, 0x01}  1.2.643.2.2.36.1  id-GostR3410-2001-CryptoPro-XchB-ParamSet
#define	PARAM_A_TK26_256	68	//'D' - {0x09, 0x2A, 0x85, 0x03, 0x07, 0x01, 0x02, 0x01, 0x01, 0x01}    1.2.643.7.1.2.1.1.1  id-tc26-gost-3410-12-256-paramSetA
#define	PARAM_B_TK26_256	0xB //'\xB' - {0x09, 0x2A, 0x85, 0x03, 0x07, 0x01, 0x02, 0x01, 0x01, 0x02}  1.2.643.7.1.2.1.1.2  id-tc26-gost-3410-12-256-paramSetB
#define	PARAM_C_TK26_256	0xC //'\xC' - {0x09, 0x2A, 0x85, 0x03, 0x07, 0x01, 0x02, 0x01, 0x01, 0x03}  1.2.643.7.1.2.1.1.3  id-tc26-gost-3410-12-256-paramSetC
#define	PARAM_D_TK26_256	0xD //'\xD' - {0x09, 0x2A, 0x85, 0x03, 0x07, 0x01, 0x02, 0x01, 0x01, 0x04}  1.2.643.7.1.2.1.1.4  id-tc26-gost-3410-12-256-paramSetD
#define	PARAM_HASH_256		70  //'F'

//Для ГОСТ-2012, ключ 512 бит, параметры хеш 34.11-2012
#define	PARAM_A_TK26_512	49	//'1' - {0x09, 0x2A, 0x85, 0x03, 0x07, 0x01, 0x02, 0x01, 0x02, 0x01}  1.2.643.7.1.2.1.2.1  id-tc26-gost-3410-12-512-paramSetA
#define	PARAM_B_TK26_512	50	//'2' - {0x09, 0x2A, 0x85, 0x03, 0x07, 0x01, 0x02, 0x01, 0x02, 0x02}  1.2.643.7.1.2.1.2.2  id-tc26-gost-3410-12-512-paramSetB
#define	PARAM_C_TK26_512	51	//'3' - {0x09, 0x2A, 0x85, 0x03, 0x07, 0x01, 0x02, 0x01, 0x02, 0x03}  1.2.643.7.1.2.1.2.3  id-tc26-gost-3410-12-512-paramSetC
#define	PARAM_HASH_512		71  //'G'

#ifndef CR_ZAG
typedef void* CR_INIT;
typedef void* CR_USER;
typedef void* CR_NET;
typedef void* CR_PKEY;
typedef void* CR_PKBASE;
typedef void* CR_HASH;
#endif

#ifdef BICR_OLDAPI

#define H_INIT 		CR_INIT*
#define H_USER 		CR_USER*
#define H_NET 		CR_NET*
#define H_PKEY 		CR_PKEY*
#define H_PKBASE 	CR_PKBASE*
#define H_HASH 		CR_HASH*
#define BICR_HANDLE void*

#else

#define BICR_HANDLE void*
typedef struct _x_H_HASH { int fake; }*H_HASH;
typedef struct _x_H_INIT { int fake; }*H_INIT;
typedef struct _x_H_NET { int fake; }*H_NET;
typedef struct _x_H_PKBASE { int fake; }*H_PKBASE;
typedef struct _x_H_PKEY { int fake; }*H_PKEY;
typedef struct _x_H_CRKEY { int fake; }*H_CRKEY;
typedef struct _x_H_USER { int fake; }*H_USER;
typedef struct _x_SOMETHING_48 { char fake[48]; } SOMETHING_48;
#endif //BICR_OLDAPI

//razmer kriptozagolovka
#define CR_HDR_SIZE 48
//razmer kriptozagolovka v novom formate
#define CR_HDR_SIZE60 60

#if defined(__cplusplus)
extern "C" {
#endif

//zagruzit GRN.DLL
int DECL cr_load_bicr_dll ( char *Apath );

#ifdef SIGN_ONLY
#define SIGN_DECL DECL
// initsializatsija biblioteki dlja BiCrypt 4.0
int SIGN_DECL cr_init_bicr4 ( char *dll_path, int tm_flag,
	int *init_mode,
	H_INIT *init_struct,
	char *prnd_filename, int flag_init_grn, int *warning );

// initsializatsija biblioteki dlja Windows 95/NT bez funktsij shifrovanija
int SIGN_DECL cr_init ( int tm_flag,
	int *init_mode,
	H_INIT *init_struct );

#else //SIGN_ONLY
// initsializatsija biblioteki dlja BiCrypt 4.0
int DECL cr_init_bicr4 ( char *dll_path, int tm_flag,
	const char *gk,
	const char *uz,
	const char *psw,
	void *tm_number,
	int *tmn_blen,
	int *init_mode,
	H_INIT *init_struct,
	char *prnd_filename, int flag_init_grn, int *warning );

// initsializatsija biblioteki dlja Windows 95/NT s funktsijami shifrovanija
int DECL cr_init ( int tm_flag,
	const char *gk,
	const char *uz,
	const char *psw,
	void *tm_number,
	int *tmn_blen,
	int *init_mode,
	H_INIT *Ainit_struct );

//gruzit GK iz bufera dliny gk_len
//gruzit UZ iz bufera dliny uz_len
int DECL cr_init_buf ( int tm_flag,
  const char *gk_buf, int gk_len,
  const char *uz_buf, int uz_len,
  const char *psw,
  void *tm_number,
  int *tmn_blen,
  int *init_mode,
  H_INIT *Ainit_struct );

//gruzit novyj GK/UZ v staryj h_init
int DECL cr_set_gkuz ( H_INIT h_init, int tm_flag, char *gk, char *uz, char *psw );

#endif //SIGN_ONLY

#define CR_TYPE_INIT	0x13485754
#define CR_TYPE_USER	0x21236512
#define CR_TYPE_PKEY	0x33036336
#define CR_TYPE_PKBASE	0x42935721
#define CR_TYPE_HASH	0x51244424
#define CR_TYPE_NET	    0x63093490

//poluchit type of HANDLE, type>>28 eto 1,2,3,4,5,6
int DECL cr_get_handle_type ( BICR_HANDLE Ahandle, int *ptr_type );

//deinitsializatsija H_INIT
int DECL cr_uninit ( H_INIT Ainit_struct );


//initsializatsija biblioteki
int DECL Bicr4_InitCritical(void);
int DECL cr_init_multithread(void);
#ifdef SIGN_ONLY
DECL8(const char*) GetLastFileErrorExp(unsigned int *LineNumber);
#else
DECL8(const char*) GetLastFileError(unsigned int *LineNumber);
#endif

//deinitsializatsija biblioteki
int DECL cr_finalize ( void );

//otkryt' hesh
int DECL cr_hash_open ( H_HASH *Ahash_struct );

//vychislit' hesh
int DECL cr_hash_calc ( H_HASH Ahash_struct,
  	void *buf,
  	int buf_len );

//vozvratit' hesh
int DECL cr_hash_return ( H_HASH Ahash_struct,
  	void *res,
  	int *res_blen );

//zakryt' hesh
int DECL cr_hash_close ( H_HASH Ahash_struct );

//sgenerirovat' master klyuch
int DECL cr_gen_masterkey ( H_INIT Ainit_structX, void *masterkey, int *master_blen );

//ystanavlivaet master-klyuch i masku
int DECL cr_install_masterkey ( H_INIT Ainit_struct, 
    void *masterkey, int master_len,
    void *masterkey_gk, int *master_blen_gk );

//sgenerirovat' klyuchi podpisi (OLDAPI)
int DECL cr_gen_elgkey ( H_INIT Ainit_struct,
  	char *password, int *passlen,
  	void *secrkey, int *secr_blen,
  	H_PKEY *Apkey_struct,
  	char *userid,
  	void *tm_number, int *tmn_blen );

//sgenerirovat' klyuchi podpisi i ne vydavat ih naruzhu
int DECL cr_gen_onetime_keypair ( H_INIT Ainit_struct,
  H_USER *Auser_struct,
  H_PKEY *Apkey_struct,
  char *userid );

//sgenerirovat' klyuchi podpisi v fail (API 4.0)
int DECL cr_gen_keypair ( H_INIT Ainit_struct,
  	char *password, int *passlen,
	char *ConfidentFilename,
  	H_PKEY *Apkey_struct,
  	char *userid );

#ifndef SIGN_ONLY
//sgenerirovat' klyuchi podpisi na master klyuche (API 4.0)
int DECL cr_gen_keypair_mk ( H_INIT Ainit_struct,
  	const void *masterkey, int master_len,
	char *ConfidentFilename,
  	H_PKEY *Apkey_struct,
  	char *userid );
#endif

//Generiruet klyuch podpisi
//esli mode=0 to rabotaet analogichno cr_gen_elgkey
//esli mode=1 togda zapisyvaet klyuch nachinaja so smeschenija 128
int DECL cr_gen_elgkey_ext ( H_INIT Ainit_struct,
	const char *userid,
	char *password, int *pass_blen,
	void *secrkey, int *secr_blen,
	int mode,
	H_PKEY *Apkey_struct, 
	void *tm_number, int *tmn_blen );

#ifndef SIGN_ONLY
//sgenerirovat' klyuchi podpisi na master klyuche (OLDAPI)
int DECL cr_gen_elgkey_mk ( H_INIT Ainit_struct,
  	const void *masterkey, int master_len,
  	void *secrkey, int *secr_blen,
  	H_PKEY *Apkey_struct,
  	char *userid,
  	void *tm_number, int *tmn_blen );

//Generiruet klyuch podpisi
//esli mode=0 to rabotaet analogichno cr_gen_elgkey_mk
//esli mode=1 togda zapisyvaet klyuch nachinaja so smeschenija 128
int DECL cr_gen_elgkey_mk_ext ( H_INIT Ainit_struct,
	const char *userid,
	const void *masterkey, int master_len,
	void *secrkey, int *secr_blen,
	int mode,
	H_PKEY *Apkey_struct,
	void *tm_number, int *tmn_blen );
#endif

//zagruzit' klyuch podpisi (OLDAPI)
int DECL cr_load_elgkey ( H_INIT Ainit_struct,
  	char *password, int pass_len,
  	void *secrkey, int secr_blen,
  	void *tm_number, int *tmn_blen,
  	char *userid, int *userid_blen,
  	H_USER *Auser_struct );

//sozdat' zatravku DSCH v file ili na tabletku (filename=NULL)
//esli flag_init_grn!=0 togda vyzyvaet klaviaturnyj DSCH
int DECL cr_init_prnd ( H_INIT Ainit_struct, char *Afilename, int flag_init_grn );

//zapisat' zatravku DSCH v file ili na tabletku (filename=NULL)
int DECL cr_write_prnd ( H_INIT Ainit_struct, char *Afilename );

//zagruzit' klyuch podpisi iz faila (API 4.0)
int DECL cr_read_skey ( H_INIT Ainit_struct,
  	char *password, int pass_len,
  	char *ConfidentFilename,
  	char *userid, int *userid_blen,
  	H_USER *Auser_struct );

//zagruzit' dopolnitel'nyj klyuch podpisi (mode=1)
//zagruzit' osnovnoj klyuch podpisi (mode=0)
int DECL cr_load_elgkey_ext ( H_INIT Ainit_struct,
  	char *password, int pass_blen,
  	void *secrkey, int secr_blen,
  	void *tm_number, int *tmn_blen,
  	char *userid, int *userid_blen,
  	int mode,
  	H_USER *Auser_struct );

#ifndef SIGN_ONLY
//zagruzit' klyuchi podpisi na master klyuche (OLDAPI)
int DECL cr_load_elgkey_mk ( H_INIT Ainit_struct,
  	void *masterkey, int master_len,
  	void *secrkey, int secr_blen,
  	void *tm_number, int *tmn_blen,
  	char *userid, int *userid_blen,
  	H_USER *Auser_struct );

//zagruzit' klyuch podpisi na master klyuche (API 4.0)
int DECL cr_read_skey_mk ( H_INIT Ainit_struct,
  	void *masterkey, int master_len,
	char *ConfidentFilename,
  	char *userid, int *userid_blen,
  	H_USER *Auser_struct );
 
//zagruzit' dopolnitel'nyj klyuch podpisi na master klyuche (mode=1)
int DECL cr_load_elgkey_mk_ext ( H_INIT Ainit_struct,
  	void *masterkey, int master_len,
  	void *secrkey, int secr_blen,
  	void *tm_number, int *tmn_blen,
  	char *userid, int *userid_blen,
  	int mode,
  	H_USER *Auser_struct );

#endif //SIGN_ONLY

//sgenerirovat' public key
int DECL cr_gen_pubkey ( H_INIT Ainit_structX,
  	H_USER Auser_struct,
  	H_PKEY *Apkey_struct );

//zakryt' deskriptor H_USER
int DECL cr_elgkey_close ( H_INIT Ainit_structX, H_USER Auser_struct );

//podpisat' bufer
int DECL cr_sign_buf ( H_INIT Ainit_structX,
  	H_USER Auser_struct,
  	void *buf, int buf_len,
  	void *sign,	int *sign_blen );

//proverit' bufer
int DECL cr_check_buf ( H_INIT Ainit_structX,
  	H_PKEY Apkey_struct,
  	void *buf, int buf_blen,
  	void *sign, int sign_blen );

//podpisat' hesh
int DECL cr_sign_hash ( H_INIT Ainit_structX,
  	H_USER Auser_struct,
  	void *hash, int hash_blen,
  	void *sign, int *sign_blen );

//proverit' hesh
int DECL cr_check_hash ( H_INIT Ainit_structX,
	H_PKEY Apkey_struct,
	void *hash, int hash_blen,
	void *sign, int sign_blen );

//vernut' nomer tabletki
int DECL cr_get_tm_number ( H_INIT Ainit_struct, 
	void *tm_number, int *tmn_blen );

//poluchit' identifikator sekretnogo klyucha
int DECL cr_elgkey_getid ( H_INIT Ainit_structX,
  	H_USER Auser_struct,
  	char *userid, int *userid_blen );

// initsalizirovat' deskriptor publichnyh klyuchej H_PKBASE dannymi iz pamjati
int DECL cr_pkbase_open_membuf ( void *membuf, int mem_blen,
	int com_blen,
	H_PKBASE* Apkbase_struct );

//initsializirovat' deskriptor publichnyh klyuchej H_PKBASE dannymi iz fajla/FPSU
int DECL cr_pkbase_load ( H_INIT Ainit_structX, 
	char *pk_file,
	int com_blen,
	int flag_modify,
	H_PKBASE* Apkbase_struct );

//initsializirovat' deskriptor publichnyh klyuchej H_PKBASE dannymi iz fajla
// flag_modify = 1 esli bazu budut modifitsirovat'
// flag_modify = 0 esli baza ostanetsja prezhnej
int DECL cr_pkbase_open ( char *pk_file, 
	int com_blen, 
	int flag_modify,
	H_PKBASE* Apkbase_struct );

//zakryt' deskriptor H_PKBASE
int DECL cr_pkbase_close ( H_PKBASE Apkbase_struct );

//zakryt' deskriptor s otkrytym klyuchom
int DECL cr_pkey_close ( H_PKEY Apkey_struct );

//proverit' nalichie otkrytogo klyucha v spravochnike
//esli najden - vozvratit' ukazatel' na nee, esli eto trebuetsja (pkey!=NULL)
int DECL cr_pkbase_find ( H_PKBASE Apkbase_struct,
   const char *userid,
   void *comment, int *com_blen,
   H_PKEY *Apkey_struct );

//dobavit' novyj ili zamenit' suschestvuyuschij publichnyj klyuch
int DECL cr_pkbase_add ( H_PKBASE Apkbase_struct,
   H_PKEY Apkey_struct,
   void *comment, int comment_blen );
   
//ubrat' publichnyj klyuch iz spravochnika
int DECL cr_pkbase_remove ( H_PKBASE Apkbase_struct,
   const char *userid );
   
//sohranit' spravochnik v fajl
int DECL cr_pkbase_save ( H_PKBASE Apkbase_struct, 
	const char *pk_file );

//ustanovka setevyh klyuchej na disk
int DECL cr_install_netkey ( H_INIT Ainit_struct, 
	const char *input_key, 
	const char *input_nkl, 
	const char *output_nkl );

//prochitat' tri stranitsy iz tabletki
int DECL cr_read_three_tm_page ( H_INIT Ainit_struct,
  	void *pagebufer );

//sozdat' deskriptor H_PKEY s odnim otkrytym klyuchom
int DECL cr_pkey_put ( void *pubkey, 
	char *namkey, 
	H_PKEY *Apkey_struct );

int DECL cr_pkey_load (H_INIT Ainit_structX,
	void *Apubkey, int pubkeyLength,
	char *namkey, char Aparam,
	H_PKEY *Apkey_struct );

// poluchit' identifikator otkrytogo klyucha
int DECL cr_pkey_getid ( H_PKEY Apkey_struct, 
	char *userid, 
	int *userid_blen );

//proverit' (flag_del=1 - udalit') podpis' nomer N dlja fajla, N>=1
int DECL cr_check_file ( H_INIT Ainit_structZ,
    H_PKBASE Apkbase_struct,
    const char *file_name, 
    int N, 
    int flag_del,
    char *userid, int *userid_blen );

//podpisat' fajl
int DECL cr_sign_file ( H_INIT Ainit_structZ,
    H_USER Auser_struct,
    const char *file_name );

//initsializiruet funktsiyu ProcentFunc dlja vyvoda protsenta ispolnenija fajla
//ProcentData mozhet soderzhat' lyubye dannye pol'zovatelja, naprimer HWND okna
//oni peredayutsja kak pervyj parametr pri posleduyuschem vyzove ProcentFunc
int DECL cr_set_procent_callback ( H_INIT Ainit_struct, 
	int(*ProcentFunc)(void*,long,long), 
	void *ProcentData );

#ifdef UNIX
int DECL cr_init_random ( void );
#else
//vyvesti na ekran okno i ozhidat' dvizhenija myshi ili nazhatija na klaviaturu
//dlja zapolnenija datchika
//hWnd - hendl okna roditelja ili NULL esli roditelja net
int DECL cr_init_random ( HWND hWnd );

//podpisat' HANDLE otkrytogo faila
int DECL cr_sign_hfile ( H_INIT Ainit_structZ,
    H_USER Auser_struct,
    HANDLE hFile );
#endif

//vozvraschaet strukturu dannyh podpisi dlja fajla
int DECL cr_file_get_sign_struct ( H_INIT Ainit_structX,
    const char *file_name, 
    int search_from, 
    void *sign, int *sign_blen, 
    char *userid, int *userid_blen,
    int *struct_blen );

//dobavljaet strukturu dannyh podpisi v konets fajla
int DECL cr_file_put_sign_struct ( H_INIT Ainit_structX,
    const char *file_name,
    void *sign, int sign_blen, 
    char *userid, int userid_blen );

//vozvraschaet strukturu dannyh podpisi dlja bufera
int DECL cr_buf_get_sign_struct ( H_INIT Ainit_structX,
    const void *buf, int buf_len, 
    int search_from, 
    void *sign, int *sign_blen, 
    char *userid, int *userid_blen,
    int *struct_blen );

//dobavljaet strukturu dannyh podpisi v konets bufera
int DECL cr_buf_put_sign_struct ( H_INIT Ainit_structX,
    void *buf, int inbuf_len, int *outbuf_len,
    void *sign, int sign_blen, 
    char *userid, int userid_blen );

//Kratkoe opisanie formata SberSign 3.1 dlja hranenija hesha v tabletke 
//  1) tabletka dolzhna byt' bolee 512 bajt razmerom
//       (eto tip 4, 6, 12)
//  2) pishetsja 30 bajt v tabletku po mestu s offsetom 256
//  3) pishetsja Crc2 ot etih 30 bajt po mestu 256+30
//     (to est' eta stranitsa budet s Crc2)
//     Vnimanie! Hesh fajla po GOST soderzhit 32 bajta, 
//     no poslednie 2 bajta v etom formate ne budut uchityvat'sja 
//     v operatsijah sravnenija i t.d. oni polagayutsja ravnym Crc2

// chitaet iz tabletki v formate SberSign 3.1
int DECL cr_read_tm ( void *buf, int *buf_blen );

// pishet v tabletku v formate SberSign 3.1
int DECL cr_write_tm ( void *buf, int buf_len );

//vozvratit' dlja raspechatki
//vnimanie! vozvraschaetsja publichnyj klyuch 256 bajt
//	dlja raspechatki dostatochno vzjat' 
//	pervye 64 bajta (dlja 512 bit podpisi)
//	ili pervye 128 bajt (dlja 1024 bit podpisi)
//	ostal'nye bajty nuzhny tol'ko dlja proverki podpisi
//	eto tak nazyvaemaja reshetka
//	reshetka mozhet byt' sgenerirovana spets.protseduroj
//      i ee ne objazatel'no raspechatyvat'
int DECL cr_pkey_getinfo ( H_PKEY Apkey_struct,
	char *userid, int *userid_blen,
	void *pkbuf, int *pkbuf_blen );

//vybrat' iz otkrytogo spravochnika pervyj klyuch
int DECL cr_pkbase_findfirst ( H_PKBASE Apkbase_struct,
	H_PKEY *Apkey_struct,
	void *comment, int *com_blen );

//vybrat' iz otkrytogo spravochnika posleduyuschie klyuchi
//vnimanie! ne pol'zujtes' protseduroj cr_pkbase_find
//	esli vy ne zakonchili vyborku vseh klyuchej
//	tak kak ona portit vnutrennij ukazatel' tekuschego klyucha
int DECL cr_pkbase_findnext ( H_PKBASE Apkbase_struct,
	H_PKEY *Apkey_struct,
	void *comment, int *com_blen );

//vozvraschaet informatsiyu ob ispol'zuemoj biblioteke
int DECL cr_get_version_info ( char *info_str, int *str_blen );

// Chitaet klyuch ETsP iz tabletki
int DECL cr_read_tmkey ( void *buf, int *buf_blen );

// Pishet klyuch ETsP v tabletku
int DECL cr_write_tmkey ( void *buf, int buf_len );

#ifndef SIGN_ONLY

//zagruzit' setevye klyuchi iz fajla
int DECL cr_netfile_load ( H_INIT Ainit_struct,
	const char* net_file,
	int flag_compr,
	H_NET* Anet_struct );

//zagruzit' setevye klyuchi iz bufera
int DECL cr_netbuf_load ( H_INIT Ainit_struct,
  	void* net_buf, int net_buf_blen,
  	int flag_compr,
  	H_NET* Anet_struct );

//zashifrovat' bufer
int DECL cr_buf_encode ( H_NET Anet_struct,
  	int num_recv,
  	const void* buf_in, unsigned int buf_in_len,
  	void* buf_out, unsigned int* out_blen );

//rasshifrovat' bufer
int DECL cr_buf_decode ( H_NET Anet_struct,
  	const void* buf_in,
  	unsigned int buf_in_len,
  	void* buf_out,
  	unsigned int* out_blen );

//vygruzit' setevye klyuchi
int DECL cr_netkey_close ( H_NET Anet_struct );

// Zashifrovat' fajl
int DECL cr_file_encode ( H_NET Anet_struct,
    int num_recv,
    const char* in_file_name,
    const char* out_file_name );

// Rasshifrovat' fajl
int DECL cr_file_decode ( H_NET Anet_struct,
    const char* in_file_name,
    const char* out_file_name );

//Zagruzhaet klyuch dlja shifrovanija na osnove publichnyh klyuchej
//na vhod podat' predvaritel'no zagruzhennye sekretnyj klyuch podpisi otpravitelja
//i publichnyj klyuch podpisi poluchatelja
//vydaet na vyhode klyuch shifrovanija my_cr_net kotoryj mozhno ispol'zovat' 
//dlja zashifrovanija ili rasshifrovanija s ispol'zovaniem standartnyh funktsij
//posle ispol'zovanija - udalit' klyuch funktsiej cr_netkey_close
int DECL cr_load_pcrypt_key ( H_INIT Ainit_struct, 
	H_USER Auser_struct, 
	H_PKEY Apkey_struct, 
	int flag_compress, 
	H_NET* Anet_struct );

//initsializiruet nachalo upakovki
int DECL cr_start_compress ( H_INIT Ainit_struct );

//pakuet blok dannyh
int DECL cr_compress_block ( H_INIT Ainit_struct,
    const void *buf_in, const unsigned int in_blen,
    void *buf_out, unsigned int *out_blen );

//initsializiruet nachalo raspakovki
int DECL cr_start_uncompress ( H_INIT Ainit_struct );

//raspakovyvaet blok dannyh
int DECL cr_uncompress_block ( H_INIT Ainit_struct,
    const void *buf_in, const unsigned int in_blen,
    void *buf_out, unsigned int *out_blen );

//szhimaet fajl dannyh
int DECL cr_file_compress ( H_INIT Ainit_struct,
    const char *in_file_name, 
    const char *out_file_name );

//razzhimaet fajl dannyh
int DECL cr_file_uncompress ( H_INIT Ainit_struct,
    const char *in_file_name, 
    const char *out_file_name );

//Generiruet glavnyj klyuch
//Esli zadan bufer gkbuf[262] - togda klyuch pishetsja v bufer
//esli zadan gkbuf=NULL - glavnyj klyuch (i uzly zameny) pishutsja v tabletku
//nachinaja so smeschenija 128 (tabletka dolzhna byt' razmerom 256 bajt)
//Uzly zameny berutsja te, kotorye byli zagruzheny v pamjat' pri cr_init
int DECL cr_gen_gk ( H_INIT Ainit_struct,
	char *password,
	void *gkbuf, int *gkblen,
	void *tm_number, int *tmn_blen );

//Kopiruet GK iz bufera v tabletku
//Uzly zameny berutsja te, kotorye byli zagruzheny v pamjat' pri cr_init
int DECL cr_gk_copy_tm ( H_INIT Ainit_struct,
	void *gkbuf, int gkblen,
	void *tm_number, int *tmn_blen );

//Kopiruet GK iz tabletki v bufer
int DECL cr_gk_read_tm ( H_INIT Ainit_struct,
	void *gkbuf, int *gkblen,
	void *uzbuf, int *uzblen,
	void *tm_number, int *tmn_blen );

/*--------------- ADDITIONAL CRYPTO FUNCTIONS 23/08/2005 ----------------*/
//Generiruet fajl s klyuchevoj tablitsej
int DECL cr_gen_netkey_table ( H_INIT Ainit_struct,
	int net_number,
	int nodes,
    char *ktabl_file,
    char *nsys_file );

//Schityvaet klyuch iz klyuchevoj tablitsy i formiruet
//fajly s etim klyuchom dlja funktsii cr_install_netkey
int DECL cr_gen_enckey ( H_INIT Ainit_struct,
	int net_number,
	int node_number,
    char *ktabl_buf, int ktabl_len,
    char *nsys_buf, int nsys_len,
    char *key_dir );

//Pereshifrovanie setevyh klyuchej
//BiKript dolzhen byt' proinitsializirovan na novom klyuche GK
//Esli vozvraschaet 0, togda pereshli na novyj GK 
//i pereshifrovali na nego fajl s klyuchami
int DECL cr_change_netkey ( H_INIT Ainit_struct, 
	char *old_key_name,
	char *new_key_name,
	char *old_gk_name,
	char *old_uz_name,
	char *old_passw );

//расширение таблицы до new_nodes узлов, уменьшить таблицу нельзя
//если задать new_nodes=0, то вернет текущее число узлов в current_nodes
int DECL cr_extend_netkey_table ( H_INIT Ainit_struct,
	char* ktabl_file, 
	char* nsys_file,
	int new_nodes,
	int* current_nodes );

#endif //SIGN_ONLY

//Vvodit v dejstvie klyuch, zapisannyj funktsijami
//cr_gen_elgkey_mk_ext cr_gen_elgkey_ext
//perepisyvaja ego iz smeschenija 128 po smescheniyu 0 vnutri tabletki
//staryj klyuch pri etom unichtozhaetsja
//Nikakih proverok validnosti klyucha ne proizvoditsja
//dlja proverki validnosti vyzovite funktsiyu chtenija klyucha - cr_load_elgkey
int DECL cr_change_elgkey ( H_INIT Ainit_struct,
	void *tm_number, int *tmn_blen );

//Vozvraschaet 32 sluchajnyh bajta
int DECL cr_get32_random ( H_INIT Ainit_structX, 
	void *data );

//----------------------------------------------------------------

// sm msdn na CryptSetHashParam(*, HP_HASHVAL, * );
int DECL cr_hash_set ( H_HASH Ahash,
 const char *hash_buf );

// sm msdn na CryptDuplicateHash(hHashSrc, *, &hHashDst );
int DECL cr_hash_dup ( const H_HASH AHashSrc,
 H_HASH *AHashDst );

#ifdef USE_UNICODE
int DECL cr_file_compressW ( H_INIT Ainit_struct,
    const wchar_t *in_file_name, 
    const wchar_t *out_file_name );

int DECL cr_file_uncompressW ( H_INIT Ainit_struct,
    const wchar_t *in_file_name, 
    const wchar_t *out_file_name );

int DECL cr_file_get_sign_structW ( H_INIT Ainit_structX,
    const wchar_t *file_name, 
    int search_from, 
    void *sign, int *sign_blen, 
    char *userid, int *userid_blen,
    int *struct_blen );

int DECL cr_file_put_sign_structW ( H_INIT Ainit_structX,
    const wchar_t *file_name,
    void *sign, int sign_blen, 
    char *userid, int userid_blen );

int DECL cr_check_fileW ( H_INIT Ainit_structZ,
    H_PKBASE Apkbase_struct,
    const wchar_t *file_name, 
    int N, 
    int flag_del,
    char *userid, int *userid_blen );

int DECL cr_sign_fileW ( H_INIT Ainit_structZ,
    H_USER Auser_struct,
    const wchar_t *file_name );

int DECL cr_file_encodeW ( H_NET Anet_struct,
    int num_recv,
    const wchar_t* in_file_name,
    const wchar_t* out_file_name );

int DECL cr_file_decodeW ( H_NET Anet_struct,
    const wchar_t* in_file_name,
    const wchar_t* out_file_name );
#endif //USE_UNICODE

//option for h_init, h_user, h_pkey, h_hash
#define OPTION_PARAM_SET 	1
#define OPTION_HASH_PAR_SET 2

int DECL cr_set_param ( BICR_HANDLE Ahandle, int option, int value );
int DECL cr_get_param ( BICR_HANDLE Ahandle, int option, int *value );

#ifdef USE_SSL
// ------- NEW -----------

//int UZTypeGost28147
//может принимать значения
#define UZType_CryptoProParamSetA    0
#define UZType_Gost28147_Param_Z     3

//int Aparam_alg
//может принимать значения
#define WPType_SIMPLE_EXPORT  1
#define WPType_PRO_EXPORT     2
#define WPType_PRO12_EXPORT   3


//============== VER5 ========================
//cr_ssl_decrypt_data2
int DECL cr_ssl_decrypt_data5( H_USER Auser_struct, int key_wp_encryption_param,
		char *macKey, int macKeyLength,
		char *encryptedKey, int encryptedKeyLength,
		char *publicKey, int publicKeyLength,
		char *UKM, int UKM_Length,
		char *IV, int IV_Length,
		char *encryptedBinData, int encryptedBinDataLength,
		int Aparam_alg, 
		int UZTypeGost28147,
		char *resultCtx, int *resultCtxLength);
//cr_ssl_encrypt_key2
int DECL cr_ssl_encrypt_key5( H_INIT Ainit_structX, 
		char *sessionKey, int sessionKeyLength,
		char *komu_pub, int komu_pub_length,
		int Aparam_set, int key_wp_encryption_param,
		int Aparam_alg,
		char *macKey, int *macKeyLength,
		char *UKM, int *UKM_Length,
		char *ephem_pub_key, int *ephem_pub_key_length,
		char *encryptedKey, int *encryptedKeyLength);
int DECL cr_ssl_encrypt_key6( H_INIT Ainit_structX, 
		char *sessionKey, int sessionKeyLength,
		char *komu_pub, int komu_pub_length,
		int Aparam_set, int flag_magma,
		char *UKM, int *UKM_Length,
		char *ephem_pub_key, int *ephem_pub_key_length,
		char *encryptedKey, int *encryptedKeyLength);
//cr_ssl_encrypt_mykey2
int DECL cr_ssl_encrypt_mykey5( H_INIT Ainit_structX, 
		H_USER Auser_struct, 
		char *sessionKey, int sessionKeyLength,
		char *komu_pub, int komu_pub_length,
		int Aparam_set, int key_wp_encryption_param,
		int Aparam_alg,
		char *macKey, int *macKeyLength,
		char *UKM, int *UKM_Length,
		char *encryptedKey, int *encryptedKeyLength);
//cr_ssl_cloud_decrypt_key2
int DECL cr_ssl_cloud_decrypt_key5( H_USER Auser_struct, int key_wp_encryption_param,
		char *macKey, int macKeyLength,
		char *encryptedKey, int encryptedKeyLength,
		char *publicKey, int publicKeyLength,
		char *UKM, int UKM_Length,
		int Aparam_alg,
		char *sessionKey, int *sessionKeyLength);
int DECL cr_ssl_cloud_decrypt_key6( H_USER user_struct, int flag_magma,
			char *encryptedKey, int encryptedKeyLength,
			char *PublicKey, int PublicKeyLength,
			char *ukm, int ukmLength,
			char *sessionKey, int *sessionKeyLength);
//-------------- NEW -------------------------
int DECL cr_ssl_cloud_decrypt_data2 ( char *sessionKey, int sessionKeyLength,
		char *IV, int IV_Length, 
		char *encryptedBinData, int encryptedBinDataLength,
		int UZTypeGost28147,
		char *resultCtx, int *resultCtxLength);
int DECL cr_ssl_cloud_decrypt_data6(int flag_magma, char *sessionKey, int sessionKeyLength, 
			char *iv, int ivlen,
			char *encryptedBinData, int encryptedBinDataLength,
			char *omac, int omacLength);
int DECL cr_ssl_cloud_decrypt_data6_first(int flag_magma, char *sessionKey, int sessionKeyLength, 
			char *iv, int ivlen,
			char *resultCtx, int *resultCtxLength);
int DECL cr_ssl_cloud_decrypt_data6_next(int flag_magma,
			char *encryptedBinData, int encryptedBinDataLength,
			char *resultCtx, int resultCtxLength);
int DECL cr_ssl_cloud_decrypt_data6_last(int flag_magma,
			char *encryptedBinData, int encryptedBinDataLength,
			char *omac, int omacLength,
			char *resultCtx, int resultCtxLength);
int DECL cr_ssl_decrypt_data2 ( H_USER Auser_struct,
		char *macKey, int macKeyLength,
		char *encryptedKey, int encryptedKeyLength,
		char *publicKey, int publicKeyLength,
		char *UKM, int UKM_Length,
		char *IV, int IV_Length,
		char *encryptedBinData, int encryptedBinDataLength,
		int Aparam_alg,
		int UZTypeGost28147,
		char *resultCtx, int *resultCtxLength);
int DECL cr_ssl_decrypt_data3 (char *encryptedBinData, int encryptedBinDataLength,
		char *Ctx, int CtxLength);
int DECL cr_ssl_cloud_decrypt_key2 ( H_USER Auser_struct,
		char *macKey, int macKeyLength,
		char *encryptedKey, int encryptedKeyLength,
		char *publicKey, int publicKeyLength,
		char *UKM, int UKM_Length,
		int Aparam_alg,
		char *sessionKey, int *sessionKeyLength);
int DECL cr_ssl_encrypt_key2 ( H_INIT Ainit_structX, 
		char *sessionKey, int sessionKeyLength,
		char *komu_pub, int komu_pub_length,
		int Aparam_set,
		int Aparam_alg,
		char *macKey, int *macKeyLength,
		char *UKM, int *UKM_Length,
		char *ephem_pub_key, int *ephem_pub_key_length,
		char *encryptedKey, int *encryptedKeyLength);
int DECL cr_ssl_encrypt_data2 ( H_INIT Ainit_structX, 
		char *buf_data, int len_data, 
		int UZTypeGost28147,
		char *IV, int *IV_Length,
		char *sessionKey, int *sessionKeyLength,
		char *resultCtx, int *resultCtxLength);
int DECL cr_ssl_encrypt_data6 ( H_INIT Ainit_structX, 
		char *buf_data, int len_data, 
		int flag_magma,
		char *IV, int *IV_Length,
		char *sessionKey, int *sessionKeyLength,
		char *omac, int *omacLength);
int DECL cr_ssl_encrypt_data6_first ( H_INIT Ainit_structX, 
		int flag_magma,
		char *IV, int *IV_Length,
		char *sessionKey, int *sessionKeyLength,
		char *resultCtx, int *resultCtxLength);
int DECL cr_ssl_encrypt_data6_next ( H_INIT Ainit_structX, 
		char *Abuf_data, int Alen_data,
		int flag_magma,
		char *resultCtx, int resultCtxLength);
int DECL cr_ssl_encrypt_data6_last ( H_INIT Ainit_structX, 
		char *Abuf_data, int Alen_data,
		int flag_magma,
		char *omac, int *omacLength,
		char *resultCtx, int resultCtxLength);
int DECL cr_ssl_encrypt_data_raw ( H_INIT Ainit_structX, 
		char *buf_data, int len_data, 
		int UZTypeGost28147,
		char *IV, int IV_Length,
		char *sessionKey, int sessionKeyLength,
		char *resultCtx, int *resultCtxLength);
int DECL cr_ssl_encrypt_data3 (char *buf_data, int len_data,
		char *Ctx, int CtxLength);
int DECL cr_ssl_encrypt_mykey2 ( H_INIT Ainit_structX, 
		H_USER Auser_struct, 
		char *sessionKey, int sessionKeyLength,
		char *komu_pub, int komu_pub_length,
		int Aparam_set,
		int Aparam_alg,
		char *macKey, int *macKeyLength,
		char *UKM, int *UKM_Length,
		char *encryptedKey, int *encryptedKeyLength);
int DECL cr_ssl_encrypt_mykey ( H_INIT Ainit_structX, H_USER Auser_struct, 
		char *encryptedKey, 
		char *macKey, 
		char *sessionKey, 
		char *UKM,
		char *komu_pub, 
		int Aparam_set);

// ------- OLD -----------
int DECL cr_ssl_cloud_decrypt_data ( char *sessionKey, 
		char *IV, 
		char *encryptedBinData, int encryptedBinDataLength);
int DECL cr_ssl_decrypt_data ( H_USER Auser_struct,
		char *macKey,
		char *encryptedKey,
		char *publicKey, 
		char *UKM, 
		char *IV, 
		char *encryptedBinData, int encryptedBinDataLength );
int DECL cr_ssl_encrypt_key ( H_INIT Ainit_structX, 
		char *encryptedKey, 
		char *macKey, 
		char *sessionKey, 
		char *UKM, 
		char *komu_pub, 
		int Aparam_set, 
		char *ephem_pub_key );
int DECL cr_ssl_encrypt_data ( H_INIT Ainit_structX, 
		char *buf_data, 
		int len_data, 
		char *IV, 
		char *sessionKey );
#endif //USE_SSL

int DECL cr_get_cert_usage_info ( H_INIT Ainit_structX, char *cert_buf, int len, 
	char *s1, int *len_s1,
	char *s2, int *len_s2,
	char *s3, int *len_s3 );

int DECL cr_imit4 ( char *imit_buf, int len );

#ifdef USE_SSL

int DECL cr_core_encrypt16 ( H_INIT Ainit_structX,
		H_CRKEY Acr_key,
		char *data, int dataLength,
		char *resultCms, int *resultCmsLength);
int DECL cr_core_decrypt16 ( H_INIT Ainit_structX,
		H_CRKEY Acr_key,
		char *cms, int cmsLength,
		char *resultData, int *resultDataLength);
int DECL cr_core_load_crkey_buf ( H_INIT Ainit_structX,
		char *gk, int gkLength,
		H_CRKEY *Acr_key
		);
int DECL cr_core_crkey_free ( H_INIT Ainit_structX,
		H_CRKEY Acr_key
		);

int DECL cr_core_cbc(char *IV, int IV_Len, char *buf, int len, int *outlen, char *key32, int key_len);
int DECL cr_core_uncbc(char *IV, int IV_Len, char *buf, int len, int *outlen, char *key32, int key_len);

#endif

int DECL cr_core_hmac_calc ( H_INIT Ainit_structX,
		H_CRKEY Acr_key,
		char *data, int dataLength,
		int Aparam,
		char *result, int *resultLength);

int DECL cr_core_hashstream(char *buf, int len, int flag, 
	SOMETHING_48 *sh, int size_sh,
	int *N, //max64
	char *hash32_F,
	char *hash64_G,
	char *hash32_H,
	int *sign_len,
	char *sign128_64,
	int *userid_len,
	char *userid33);

#if defined(__cplusplus)
} //extern "C"
#endif

#define ENC_G28147			0
#define ENC_GR3412_M		11
#define ENC_GR3412_K		12
#define ENC_GR3412_OMAC_M	13
#define ENC_GR3412_OMAC_K	14

#endif


