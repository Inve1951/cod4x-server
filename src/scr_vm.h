/*
===========================================================================
    Copyright (C) 2010-2013  Ninja and TheKelm

    This file is part of CoD4X18-Server source code.

    CoD4X18-Server source code is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    CoD4X18-Server source code is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>
===========================================================================
*/



#ifndef __SCR_VM_H__
#define __SCR_VM_H__



#include "q_shared.h"
#include "q_math.h"
#include "entity.h"
#include "player.h"
#include "g_hud.h"
#include "filesystem.h"
#include "g_sv_shared.h"


typedef struct{
	uint16_t emptystring;
	uint16_t active;
	uint16_t j_spine4;
	uint16_t j_helmet;
	uint16_t j_head;
	uint16_t all;
	uint16_t allies;
	uint16_t axis;
	uint16_t bad_path;
	uint16_t begin_firing;
	uint16_t cancel_location;
	uint16_t confirm_location;
	uint16_t crouch;
	uint16_t current;
	uint16_t damage;
	uint16_t dead;
	uint16_t death;
	uint16_t detonate;
	uint16_t direct;
	uint16_t dlight;
	uint16_t done;
	uint16_t empty;
	uint16_t end_firing;
	uint16_t entity;
	uint16_t explode;
	uint16_t failed;
	uint16_t fraction;
	uint16_t free;
	uint16_t goal;
	uint16_t goal_changed;
	uint16_t goal_yaw;
	uint16_t grenade;
	uint16_t grenade_danger;
	uint16_t grenade_fire;
	uint16_t grenade_pullback;
	uint16_t info_notnull;
	uint16_t invisible;
	uint16_t key1;
	uint16_t key2;
	uint16_t killanimscript;
	uint16_t left;
	uint16_t light;
	uint16_t movedone;
	uint16_t noclass;
	uint16_t none;
	uint16_t normal;
	uint16_t player;
	uint16_t position;
	uint16_t projectile_impact;
	uint16_t prone;
	uint16_t right;
	uint16_t reload;
	uint16_t reload_start;
	uint16_t rocket;
	uint16_t rotatedone;
	uint16_t script_brushmodel;
	uint16_t script_model;
	uint16_t script_origin;
	uint16_t snd_enveffectsprio_level;
	uint16_t snd_enveffectsprio_shellshock;
	uint16_t snd_channelvolprio_holdbreath;
	uint16_t snd_channelvolprio_pain;
	uint16_t snd_channelvolprio_shellshock;
	uint16_t stand;
	uint16_t suppression;
	uint16_t suppression_end;
	uint16_t surfacetype;
	uint16_t tag_aim;
	uint16_t tag_aim_animated;
	uint16_t tag_brass;
	uint16_t tag_butt;
	uint16_t tag_clip;
	uint16_t tag_flash;
	uint16_t tag_flash_11;
	uint16_t tag_flash_2;
	uint16_t tag_flash_22;
	uint16_t tag_flash_3;
	uint16_t tag_fx;
	uint16_t tag_inhand;
	uint16_t tag_knife_attach;
	uint16_t tag_knife_fx;
	uint16_t tag_laser;
	uint16_t tag_origin;
	uint16_t tag_weapon;
	uint16_t tag_player;
	uint16_t tag_camera;
	uint16_t tag_weapon_right;
	uint16_t tag_gasmask;
	uint16_t tag_gasmask2;
	uint16_t tag_sync;
	uint16_t target_script_trigger;
	uint16_t tempEntity;
	uint16_t top;
	uint16_t touch;
	uint16_t trigger;
	uint16_t trigger_use;
	uint16_t trigger_use_touch;
	uint16_t trigger_damage;
	uint16_t trigger_lookat;
	uint16_t truck_cam;
	uint16_t weapon_change;
	uint16_t weapon_fired;
	uint16_t worldspawn;
	uint16_t flashbang;
	uint16_t flash;
	uint16_t smoke;
	uint16_t night_vision_on;
	uint16_t night_vision_off;
	uint16_t MOD_UNKNOWN;
	uint16_t MOD_PISTOL_BULLET;
	uint16_t MOD_RIFLE_BULLET;
	uint16_t MOD_GRENADE;
	uint16_t MOD_GRENADE_SPLASH;
	uint16_t MOD_PROJECTILE;
	uint16_t MOD_PROJECTILE_SPLASH;
	uint16_t MOD_MELEE;
	uint16_t MOD_HEAD_SHOT;
	uint16_t MOD_CRUSH;
	uint16_t MOD_TELEFRAG;
	uint16_t MOD_FALLING;
	uint16_t MOD_SUICIDE;
	uint16_t MOD_TRIGGER_HURT;
	uint16_t MOD_EXPLOSIVE;
	uint16_t MOD_IMPACT;
	uint16_t script_vehicle;
	uint16_t script_vehicle_collision;
	uint16_t script_vehicle_collmap;
	uint16_t script_vehicle_corpse;
	uint16_t turret_fire;
	uint16_t turret_on_target;
	uint16_t turret_not_on_target;
	uint16_t turret_on_vistarget;
	uint16_t turret_no_vis;
	uint16_t turret_rotate_stopped;
	uint16_t turret_deactivate;
	uint16_t turretstatechange;
	uint16_t turretownerchange;
	uint16_t reached_end_node;
	uint16_t reached_wait_node;
	uint16_t reached_wait_speed;
	uint16_t near_goal;
	uint16_t veh_collision;
	uint16_t veh_predictedcollision;
	uint16_t auto_change;
	uint16_t back_low;
	uint16_t back_mid;
	uint16_t back_up;
	uint16_t begin;
	uint16_t call_vote;
	uint16_t freelook;
	uint16_t head;
	uint16_t intermission;
	uint16_t j_head_dup;
	uint16_t manual_change;
	uint16_t menuresponse;
	uint16_t neck;
	uint16_t pelvis;
	uint16_t pistol;
	uint16_t plane_waypoint;
	uint16_t playing;
	uint16_t spectator;
	uint16_t vote;
	uint16_t sprint_begin;
	uint16_t sprint_end;
	uint16_t tag_driver;
	uint16_t tag_passenger;
	uint16_t tag_gunner;
	uint16_t tag_wheel_front_left;
	uint16_t tag_wheel_front_right;
	uint16_t tag_wheel_back_left;
	uint16_t tag_wheel_back_right;
	uint16_t tag_wheel_middle_left;
	uint16_t tag_wheel_middle_right;
	uint16_t script_vehicle_collision_dup;
	uint16_t script_vehicle_collmap_dup;
	uint16_t script_vehicle_corpse_dup;
	uint16_t tag_detach;
	uint16_t tag_popout;
	uint16_t tag_body;
	uint16_t tag_turret;
	uint16_t tag_turret_base;
	uint16_t tag_barrel;
	uint16_t tag_engine_left;
	uint16_t tag_engine_right;
	uint16_t front_left;
	uint16_t front_right;
	uint16_t back_left;
	uint16_t back_right;
	uint16_t tag_gunner_pov;
}stringIndex_t;

extern stringIndex_t scr_const;


typedef void (*xfunction_t)();

typedef struct scr_function_s
{
	struct scr_function_s	*next;
	char			*name;
	xfunction_t		function;
	qboolean		developer;
} scr_function_t;



typedef byte PrecacheEntry[8192];
typedef unsigned int sval_u;

#ifndef SCR_ENTREF_DEFINED
#define SCR_ENTREF_DEFINED
typedef int scr_entref_t;
#endif
/**************** Additional *************************/

typedef enum{
    SCR_CB_SAY,
    SCR_CB_SCRIPTCOMMAND
}script_CallBacks_new_t;

extern int script_CallBacks_new[8];

typedef enum fieldtype_e
{
    F_INT = 0x0,
    F_FLOAT = 0x1,
    F_LSTRING = 0x2,
    F_STRING = 0x3,
    F_VECTOR = 0x4,
    F_ENTITY = 0x5,
    F_VECTORHACK = 0x6,
    F_OBJECT = 0x7,
    F_UNKNOWN = 0x8,
	F_MODEL = 0x9
} fieldtype_t;

typedef struct client_fields_s
{
    const char *name;
    int ofs;
    fieldtype_t type;
    void (__cdecl *setter)(gclient_t *, struct client_fields_s *);
    void (__cdecl *getter)(gclient_t *);
}client_fields_t;

typedef struct ent_field_s
{
  const char *name;
  int ofs;
  fieldtype_t type;
  void (__cdecl *callback)(gentity_t *, int);
} ent_field_t;

typedef enum
{
    SCR_UNK,
    SCR_POINTER,
    SCR_STRING,
    SCR_ISTRING, //(Localized String)
    SCR_VECTOR,
    SCR_FLOAT,
    SCR_INT
}scriptVarType_t;

typedef struct
{
    unsigned short type;
    unsigned short size;
}scrTypeSize_t;

struct VariableStackBuffer
{
  const char *pos;
  uint16_t size;
  uint16_t bufLen;
  uint16_t localId;
  char time;
  char buf[1];
};

/* 7500 */
union VariableUnion
{
  int intValue;
  float floatValue;
  unsigned int stringValue;
  const float *vectorValue;
  const char *codePosValue;
  unsigned int pointerValue;
  struct VariableStackBuffer *stackValue;
  unsigned int entityOffset;
};

#pragma pack(push, 1)
/* 7512 */
union ObjectInfo_u
{
  uint16_t size;
  uint16_t entnum;
  uint16_t nextEntId;
  uint16_t self;
};


/* 7513 */
struct ObjectInfo
{
  uint16_t refCount;
  union ObjectInfo_u u;
};

/* 7514 */
union VariableValueInternal_u
{
  uint16_t next;
  union VariableUnion u;
  struct ObjectInfo o;
};

/* 7515 */
union VariableValueInternal_w
{
  unsigned int status;
  unsigned int type;
  unsigned int name;
  unsigned int classnum;
  unsigned int notifyName;
  unsigned int waitTime;
  unsigned int parentLocalId;
};

/* 7516 */
union VariableValueInternal_v
{
  uint16_t next;
  uint16_t index;
};


typedef struct
{
  union VariableUnion u;
  int type;
}VariableValue;

/* 7510 */
union Variable_u
{
  uint16_t prev;
  uint16_t prevSibling;
};

/* 7511 */
struct Variable
{
  uint16_t id;
  union Variable_u u;
};

/* 7517 */
typedef struct 
{
  struct Variable hash;
  union VariableValueInternal_u u;
  union VariableValueInternal_w w;
  union VariableValueInternal_v v;
  uint16_t nextSibling;
}VariableValueInternal;


typedef struct
{
  const char *fieldBuffer;
  uint16_t canonicalStrCount;
  byte developer;
  byte developer_script;
  byte evaluate;
  byte pad[3];
  const char *error_message;
  int error_index;
  unsigned int time;
  unsigned int timeArrayId;
  unsigned int pauseArrayId;
  unsigned int levelId;
  unsigned int gameId;
  unsigned int animId;
  unsigned int freeEntList;
  unsigned int tempVariable;
  byte bInited;
  byte pad2;
  uint16_t savecount;
  unsigned int checksum;
  unsigned int entId;
  unsigned int entFieldName;
  struct HunkUser *programHunkUser;
  const char *programBuffer;
  const char *endScriptBuffer;
  uint16_t saveIdMap[24574];
  uint16_t saveIdMapRev[24574];
}scrVarPub_t;


struct function_stack_t
{
  const char *pos;
  unsigned int localId;
  unsigned int localVarCount;
  VariableValue *top;
  VariableValue *startTop;
};


struct function_frame_t
{
  struct function_stack_t fs;
  int topType;
};

typedef struct
{
  unsigned int *localVars;
  VariableValue *maxstack;
  int function_count;
  struct function_frame_t *function_frame;
  VariableValue *top;
  byte debugCode;
  byte abort_on_error;
  byte terminal_error;
  byte pad;
  unsigned int inparamcount;
  unsigned int outparamcount;
  struct function_frame_t function_frame_start[32];
  VariableValue stack[2048];
}scrVmPub_t;

struct scrVmGlob_t
{
  VariableValue eval_stack[2];
  const char *dialog_error_message;
  int loading;
  int starttime;
  unsigned int localVarsStack[2048];
};

struct __attribute__((aligned (64))) scrVarGlob_t
{
  VariableValueInternal variableList[98304];
};

struct scrCompilePub_t
{
  int value_count;
  int far_function_count;
  unsigned int loadedscripts;
  unsigned int scriptsPos;
  unsigned int builtinFunc;
  unsigned int builtinMeth;
  uint16_t canonicalStrings[65536];
  const char *in_ptr;
  const char *parseBuf;
  byte script_loading;
  byte allowedBreakpoint;
  int16_t pad;
  int developer_statement;
  char *opcodePos;
  unsigned int programLen;
  int func_table_size;
  int func_table[1024];
};
#pragma pack(pop)

struct scr_animtree_t
{
  struct XAnim_s *anims;
};

struct scrAnimPub_t
{
  unsigned int animtrees;
  unsigned int animtree_node;
  unsigned int animTreeNames;
  struct scr_animtree_t xanim_lookup[2][128];
  unsigned int xanim_num[2];
  unsigned int animTreeIndex;
  bool animtree_loading;
};

struct scrAnimGlob_t
{
  const char *start;
  const char *pos;
  uint16_t using_xanim_lookup[2][128];
  int bAnimCheck;
};

struct SourceBufferInfo
{
  const char *codePos;
  char *buf;
  const char *sourceBuf;
  int len;
  int sortedIndex;
  bool archive;
  byte pad[3];
};



struct scrParserPub_t
{
  struct SourceBufferInfo *sourceBufferLookup;
  unsigned int sourceBufferLookupLen;
  const char *scriptfilename;
  const char *sourceBuf;
};

#define MAX_SCRIPT_FILEHANDLES 10

typedef enum{
    SCR_FH_FILE,
    SCR_FH_PARALIST,
    SCR_FH_INDEXPARALIST
}scr_fileHandleType_t;


typedef struct{
    FILE* fh;
    scr_fileHandleType_t type;
    char filename[MAX_QPATH];
    int baseOffset;
    int fileSize;
}scr_fileHandle_t;


#ifdef __cplusplus
extern "C"{
#endif


void __cdecl Scr_InitVariables(void);			//VM
void __cdecl Scr_Init(void);			//VM_Init
void __cdecl Scr_Settings(int, int, int);
void __cdecl Scr_AddEntity(gentity_t* ent);
void __cdecl Scr_Cleanup(void);
void __cdecl GScr_Shutdown(void);
int __cdecl Scr_AllocArray();
int __cdecl AllocObject();
int __cdecl Scr_GetNumParam( void );
int __cdecl Scr_GetInt( unsigned int );
float __cdecl Scr_GetFloat( unsigned int );
char* __cdecl Scr_GetString( unsigned int );
gentity_t* __cdecl Scr_GetEntity( unsigned int );
short __cdecl Scr_GetConstString( unsigned int );
unsigned int __cdecl Scr_GetType( unsigned int );
unsigned int __cdecl Scr_GetPointerType( unsigned int );
void __cdecl Scr_GetVector( unsigned int, float* );
unsigned int __cdecl Scr_GetObject( unsigned int );
void __cdecl Scr_GetObjectField(unsigned int classnum, int entnum, int offset);
const char *__cdecl Scr_GetIString(unsigned int index);

int Scr_GetFunc(unsigned int paramnum);
extern char* (__cdecl *Scr_GetLocalizedString)(unsigned int arg);

/* Scr_Error
 *
 * Throws script runtime error with 'string' description.
 * Asterisk points to function name.
 */
void __cdecl Scr_Error( const char *string);
void __cdecl Scr_SetLoading( qboolean );

/* Scr_ParamError
 *
 * Throws script runtime error with 'string' description.
 * Asterisk points to 'paramNum' function parameter.
 */
void __cdecl Scr_ParamError( int paramNum, const char *string);

/* Scr_ObjectError
 *
 * Throws script runtime error with 'string' description.
 * Asterisk points to function caller.
 */
void __cdecl Scr_ObjectError( const char *string);

void __cdecl Scr_AddInt(int value);
void __cdecl Scr_AddFloat(float);
void __cdecl Scr_AddBool(qboolean);
void __cdecl Scr_AddString(const char *string);
void __cdecl Scr_AddConstString(int strindex);
void __cdecl Scr_AddUndefined(void);
void __cdecl Scr_AddVector( vec3_t vec );
void __cdecl Scr_AddArray( void );
void __cdecl Scr_MakeArray( void );
void __cdecl Scr_AddArrayKey( int strIdx );
void __cdecl Scr_Notify( gentity_t*, unsigned short, unsigned int);
void __cdecl Scr_NotifyNum( int, unsigned int, unsigned int, unsigned int);
/*Not working :(  */
void __cdecl Scr_PrintPrevCodePos( int printDest, const char* pos, qboolean unk2 );
int __cdecl Scr_GetFunctionHandle( const char* scriptName, const char* labelName);
short __cdecl Scr_ExecEntThread( gentity_t* ent, int callbackHook, unsigned int numArgs);
short __cdecl Scr_ExecThread( int callbackHook, unsigned int numArgs);
void __cdecl Scr_FreeThread( short threadId);
unsigned int __cdecl Scr_CreateCanonicalFilename( const char* name );
//Unknown real returntype
unsigned int __cdecl FindVariable( unsigned int, unsigned int );
unsigned int __cdecl FindObject( unsigned int );
unsigned int __cdecl GetNewVariable( unsigned int, unsigned int );
void * __cdecl TempMalloc( int );
void __cdecl ScriptParse( sval_u* , byte);
unsigned int __cdecl SGetObjectA( unsigned int );
unsigned int __cdecl GetVariable( unsigned int, unsigned int );
void __cdecl ScriptCompile( sval_u, unsigned int, unsigned int, PrecacheEntry*, int);
void* __cdecl Scr_AddSourceBuffer( const char*, const char*, const char*, byte );
void __cdecl Scr_InitAllocNode( void );
void __cdecl Scr_BeginLoadScripts( void );
void __cdecl Scr_SetClassMap( unsigned int );
void __cdecl Scr_AddClassField(unsigned int classnum, const char* name, unsigned short int offset);
void __cdecl Scr_SetGenericField( void*, fieldtype_t, int );
void __cdecl Scr_GetGenericField( void*, fieldtype_t, int );
void __cdecl Scr_SetString(unsigned short *strindexptr, unsigned const stringindex);
int __cdecl Scr_AllocString(const char* string);
void Scr_InitSystem();
int GetArraySize(int);
void RemoveRefToValue(scriptVarType_t type, union VariableUnion val);

void __cdecl GScr_AddFieldsForHudElems( void );
void __cdecl GScr_AddFieldsForRadiant( void );
void __cdecl Scr_AddHudElem( game_hudelem_t* );
void __cdecl Scr_FreeHudElem( game_hudelem_t* );
void __cdecl Scr_EndLoadScripts( void );
void __cdecl Scr_ConstructMessageString( int, int, const char*, char*, unsigned int );

qboolean Scr_PlayerSay(gentity_t*, int mode, const char* text);
qboolean Scr_ScriptCommand(int clientnum, const char* cmd, const char* args);

void GScr_LoadGameTypeScript(void);
unsigned int Scr_LoadScript(const char* scriptname, PrecacheEntry *precache, int iarg_02);
qboolean Scr_ExecuteMasterResponse(char* s);
void Scr_AddStockFunctions();
void Scr_AddStockMethods();

qboolean Scr_AddFunction( const char *cmd_name, xfunction_t function, qboolean developer);
qboolean Scr_RemoveFunction( const char *cmd_name );
void Scr_ClearFunctions( void );
__cdecl void* Scr_GetFunction( const char** v_functionName, qboolean* v_developer );
qboolean Scr_AddMethod( const char *cmd_name, xfunction_t function, qboolean developer);
qboolean Scr_RemoveMethod( const char *cmd_name );
void Scr_ClearMethods( void );
__cdecl void* Scr_GetMethod( const char** v_functionName, qboolean* v_developer );
void __regparm3 VM_Notify(int, int, VariableValue* val);
int __cdecl FindEntityId(int, int);


qboolean Scr_FS_CloseFile( scr_fileHandle_t* f );
int Scr_FS_ReadLine( void *buffer, int len, fileHandle_t f );
qboolean Scr_FS_AlreadyOpened(char* qpath);
qboolean Scr_FS_FOpenFile( const char *filename, fsMode_t mode, scr_fileHandle_t* f );
fileHandle_t Scr_OpenScriptFile( char* qpath, scr_fileHandleType_t ft, fsMode_t mode);
qboolean Scr_CloseScriptFile( fileHandle_t fh);
int Scr_FS_Read( void *buffer, int len, fileHandle_t f );
int Scr_FS_Write( const void *buffer, int len, fileHandle_t h );
int Scr_FS_Seek( fileHandle_t f, long offset, int origin );
qboolean Scr_FileExists( const char* filename );

void GScr_MakeCvarServerInfo(void);
void GScr_SetCvar();
void GScr_GetCvarFloat();
void GScr_GetCvarInt();
void GScr_GetCvar();
void GScr_AddScriptCommand();
void RuntimeError(char *a3, int arg4, char *message, char *a4);
void ClientScr_GetName(gclient_t* gcl);
const char* Scr_GetPlayername(gentity_t* gent);
void Scr_FreeValue(unsigned int id);
qboolean __cdecl Scr_IsValidGameType(const char *pszGameType);
void __cdecl MT_DumpTree( );
void __cdecl Scr_DumpScriptThreads( );

// Safe function to get gentity for num passed by script call "ent function()"
gentity_t* VM_GetGEntityForNum(scr_entref_t num);
gclient_t* VM_GetGClientForEntity(gentity_t* ent);
gclient_t* VM_GetGClientForEntityNumber(scr_entref_t num);
client_t* VM_GetClientForEntityNumber(scr_entref_t num); // Mainly for pressed buttons detection.

void __noreturn CompileError(unsigned int sourcePos, const char *msg, ...);
void __cdecl RemoveVariable(unsigned int parentId, unsigned int unsignedValue);
unsigned int __cdecl GetArray(unsigned int id);
unsigned int __cdecl Scr_GetSelf(unsigned int threadId);
unsigned int __cdecl GetArrayVariable(unsigned int parentId, unsigned int unsignedValue);
void __cdecl SetVariableValue(unsigned int id, VariableValue *value);
void __cdecl CScr_GetObjectField(unsigned int classnum, int entnum, int clientNum, int offset);
// Returns pointer to new 'fields_1' array. To be used in patching purposes.
ent_field_t* __internalGet_fields_1();
void __cdecl Scr_ParseGameTypeList();

#ifdef __cplusplus
}
#endif

extern struct scrVmGlob_t scrVmGlob;
extern struct scrAnimGlob_t scrAnimGlob;

extern struct scrVarGlob_t scrVarGlob;
#define SCR_VARHIGH 32770
extern scrVarPub_t scrVarPub;
extern scrVmPub_t scrVmPub;
extern struct scrCompilePub_t scrCompilePub;
extern stringIndex_t stringIndex;
extern int g_script_error_level;
extern struct scrAnimPub_t scrAnimPub;
extern struct scrParserPub_t scrParserPub;

#endif
