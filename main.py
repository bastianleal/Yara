'''The Yara API Challenge
Instrucciones :
Como equipo de seguridad informática tenemos la necesidad de buscar en textos y binarios algunos 
patrones que pueden ir desde información sensible hasta malware. Para eso necesitamos integrar Yara
con una API que nos permita manejar reglas y analizar estos archivos o textos en busca de estos patrones. 
Es importante que como esta API va a tener bastante trafico, no tenga que cargar las reglas cada vez que
tenga que hacer un análisis. Se puede implementar con el lenguaje de programación que prefieras, frameworks
y librerias que creas necesarios pero si es importante usar Docker para que sea reproducible facilmente
y podamos probarlo. El challenge consta de una implementación básica y dos optativas y algunos extras.'''


'''Solicitado por: Mercado Libre
Autor: Bastian Leal
Fecha: Enero 2022
Lenguaje: Python
BBDD: Sqlite3
Framework:Flask Api'''

#declaracion de librerias Utilizadas 
#Framework utilizado: Flask API documentacion Oficial: https://flask.palletsprojects.com/en/2.0.x/
import collections
import datetime
import json
import yara
import bbddsqlite3

from flask import Flask, request
from flask_api import status

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = './Archivos'

#comandos para ejecucion en entorno local:
#set FLASK_APP=main
#> flask run --reload
# * Running on http://127.0.0.1:5000/

from datetime import date

'''Primer Endpoint /api/rule'''
#Endpoint #1 
#en el sigueinte Endpoint se ingresara una regla Yara, cumpliendo con los parametros indicados:
'''
Add rule
Metodo: POST Path: /api/rule Body:
{
    "name":"esto no es coca papi rule",
    "rule":"rule EstoNoEsCocaPapiRule\r\n{\r\n strings:\r\n $my_text_string = \"esto no es coca papi\"\r\n condition:\r\n $my_text_string\r\n}"
}
'''
@app.route('/api/rule', methods=['POST'])
def rule():
    try:
        #obtenemos fechas actuales para insertar regla
        fecha = date.today()
        fecha_completa = datetime.datetime.now()
        #consultamos por los datos ingresados y los guardamos en variable record
        record = json.loads(request.data)
        #controlamos la cantidad de parametros a ingresar en request
        if (len(record)==2):

            #control de error en compilacion de regla Yara
            try:
                rule = yara.compile(source=record.get("rule"))
                aux=True
            except Exception:
                aux=False
                return json.dumps({'status': 'ok', 'error': 'Problema al compilar Regla Yara'}), status.HTTP_400_BAD_REQUEST      
            #control de error en compilacion de Match en regla Yara
            if aux:
                try:
                    rule.match(data=record.get("name"))
                    aux=True
                except Exception:
                    aux=False
                    # en caso de no ejecutar la funcion match para la regla declarada, capturamos el error
                    return json.dumps({'status': 'fail', 'error': 'Json fuera de formato'}), status.HTTP_400_BAD_REQUEST
            else:
                return json.dumps({'status': 'ok', 'error': 'Problema al compilar Regla Yara'}), status.HTTP_400_BAD_REQUEST
            
            if aux:
                #conexion a la bbdd
                con=bbddsqlite3.sql_connection()
                cursorObj = con.cursor()
                #guardamos las variables obtenidas desde el request
                nombre_regla=record.get("name")
                regla=record.get("rule")
                try: 
                    #ejecucion en BBDD segun datos ingresados, en modelo se incluye para las variables not null and unique
                    last_id=(cursorObj.execute("INSERT INTO reglas_yara(nombre_regla,regla,fecha_creacion,fecha_completa) VALUES(?,?,?,?)",(nombre_regla,regla,fecha,fecha_completa)).lastrowid)
                    aux=True
                    con.commit()
                    con.close()
                #captura error de insert en BBDD
                except Exception:
                    aux=False
                    return json.dumps({'status': 'fail', 'error': 'error en insert de BBDD Regla ya creada (nombre y regla unicos)'}), status.HTTP_409_CONFLICT
                    
            if aux:
                    salida={}
                    salida['id']=last_id
                    salida['nombre_regla']=nombre_regla
                    salida['regla']=regla
                    
                    return json.dumps(salida), status.HTTP_200_OK
        else:
            return json.dumps({'status': 'fail', 'results': 'Cantidad de parametros incorrectos'}), status.HTTP_400_BAD_REQUEST # error 500

    except Exception:
        return json.dumps({'status': 'fail', 'results': 'Parametros incorrectos'}),status.HTTP_400_BAD_REQUEST # error 500

#OK
@app.route('/api/analyze/text', methods=['POST'])
def analyzetext():
    try:
        resultados = []
        record = json.loads(request.data)
        if (len(record)==2):
            
            if (record.get("rules")) and (record.get("text")):
                aux=True
            else:
                aux=False
                return json.dumps({'status': 'fail', 'results': 'error en datos de ingreso'}),status.HTTP_400_BAD_REQUEST
            
            con=bbddsqlite3.sql_connection()
            cursorObj = con.cursor()
            for item in enumerate(record.get("rules",[])): #texto a analizar
                
                try:
                    resultado=cursorObj.execute("select regla from reglas_yara where id = ?",[item['rule_id']])
                    data=resultado.fetchall()
                    print(len(data))
                    if (len(data))>0:
                        for row in data:  
                            regla_yara = ''.join(row)
                            rule=yara.compile(source=regla_yara) 
                            matches=rule.match(data=record.get("text", "")) #validar match de regla 
                            if len(matches) > 0:  
                                resultados.append({'rule_id':item['rule_id'],'matched': True})
                                #regla existe y match
                            else:
                                
                                resultados.append({'rule_id':item['rule_id'],'matched': False})#regla existe y no match
                    else:
                        resultados.append({'rule_id': item['rule_id'], 'matched': False})   
                    
                    aux=True
                except Exception:
                    aux=False
                    resultados.append({'rule_id': item['rule_id'], 'matched': False})#regla existe y no match
            salida={}
            
            if aux:
                salida=json.dumps(resultados)
            
            return (salida), status.HTTP_201_CREATED  
        else:
            return json.dumps({'status': 'fail', 'results': 'Cantidad de parametros incorrectos'}), status.HTTP_400_BAD_REQUEST 
        
          
    except Exception:
        
        return json.dumps({'status': 'fail', 'results': 'error en datos de ingreso'}),status.HTTP_400_BAD_REQUEST

#OK
@app.route('/api/analyze/file', methods=['POST'])
def analyzefile():
    try:
        #arreglo para reglas del documento
        reglas_documento=[]
        resultados = []
        f = request.files['file']

        #guardamos las reglas del formulario, ademas se transforman en variables enteras
        if request.form['rule']:
            reglas=request.form['rule']
            reglas_formulario=reglas.split(sep=',')
            result = [int(item) for item in reglas_formulario]
            aux=True
        else:
            return json.dumps({'status': 'fail', 'error': 'Parametros incorrectos'}),status.HTTP_400_BAD_REQUEST
        
        try:
            texto=f.stream.read()       #lectura de archivo
            valor=texto.decode("utf-8") #decodificacion archivo 
            record=json.loads(valor)    #archivo es guardado en record como json
        except Exception:
            return json.dumps({'status': 'fail', 'error': 'Parametros incorrectos'}),status.HTTP_400_BAD_REQUEST
        
        #for para guardar valores de id de reglas incluidas en adjunto, en arreglo de reglas de documento
        for i in range(len(record["rules"])):
            reglas_documento.append(record["rules"][i]["rule_id"])

        #validamos que ambos arreglos sean iguales
        if(collections.Counter(result)==collections.Counter(reglas_documento)):
            aux=True
            con=bbddsqlite3.sql_connection()
            cursorObj = con.cursor()
            for item in enumerate(record.get("rules",[])): #texto a analizar
                
                try:
                    resultado=cursorObj.execute("select regla from reglas_yara where id = ?",[item['rule_id']])
                    data=resultado.fetchall()
                    print(len(data))
                    if (len(data))>0:
                        for row in data:  
                            regla_yara = ''.join(row)
                            rule = yara.compile(source=regla_yara) 
                            matches = rule.match(data=record.get("text", "")) #validar match de regla 
                            if len(matches) > 0:  
                                resultados.append({'rule_id': item['rule_id'], 'matched': True})
                                #regla existe y match
                            else:
                                
                                resultados.append({'rule_id': item['rule_id'], 'matched': False})#regla existe y no match
                    else:
                        resultados.append({'rule_id': item['rule_id'], 'matched': False})   
                    
                    aux=True
                except Exception:
                    aux=False
                    resultados.append({'rule_id': item['rule_id'], 'matched': False})#regla existe y no match
            salida={}
            
            if aux:
                salida=json.dumps(resultados)
            return (salida), status.HTTP_201_CREATED
        else:
            return json.dumps({'status': 'fail', 'error': 'incongruencia de reglas a consultar'}),status.HTTP_400_BAD_REQUEST     
                      
    except Exception:
        
        return json.dumps({'status': 'fail', 'error': 'Parametros incorrectos'}),status.HTTP_400_BAD_REQUEST



@app.route('/api/rule', methods=['PUT'])
def put_rule():
    try:
        record = json.loads(request.data)
        # rule = yara.compile(source=record.get("rule"))
        # matches = rule.match(data=record.get("name"))
        print(record)
        id=record.get("id")
        print(id)
        nombre_regla=record.get("name")
        regla=record.get("rule")

        con=bbddsqlite3.sql_connection()
        bbddsqlite3.actualizar_regla(con,id,nombre_regla)
        return (record)
        #print(data)
        #return json.dumps(matches)
        #if len(matches) > 0:
    #     if matches == True:
    #         return json.dumps({'status': 'ok', 'results': {"rule": matches[0].rule, "tags": list(matches[0].tags), "strings": str(matches[0].strings)}}),status.HTTP_201_CREATED
    #     else:
    #         return json.dumps({'status': 'ok', 'results': []}), status.HTTP_201_CREATED
    except Exception:
        return json.dumps({'status': 'fail', 'results': []}),status.HTTP_400_BAD_REQUEST

@app.route('/api/rule', methods=['GET'])
def get_rule():
    try:
        salida=[]
        json_output={}
        record = json.loads(request.data)
        id=record.get("id")
        print(id)
        aux=True
        try:
            if id=="ALL":
                    con=bbddsqlite3.sql_connection()
                    cursorObj = con.cursor()
                    
                    resultado=cursorObj.execute("select id,nombre_regla,regla from reglas_yara")
                    for row in resultado:
                                print(row)
                                json_output = json.dumps(row)
                                salida.append(json_output)
                    
                        
                    con.commit()
                    con.close()
                    aux=True
                #print(len(id))
            if len(id)==1:
                    con=bbddsqlite3.sql_connection()
                    cursorObj = con.cursor()
                    resultado=cursorObj.execute("select id,nombre_regla,regla from reglas_yara where id = ?",(id))
                    data=resultado.fetchall()
                    if len(data)>0: 
                        for row in data:
                            print(row)
                            jsonObj = json.dumps(row)
                            return jsonObj
                    else:
                        json_output=({id:" regla no encontrada"})
                        salida.append(json_output) 
                    con.commit()
                    con.close()
                    aux=True
                #caso donde se consulta por mas de una regla
            if len(id) > 1:
                    #reglas_separadas=id.split(sep=',')
                    reglas_noduplicado=id.split(sep=',')
                    reglas_set=set(reglas_noduplicado)
                    listanueva=list(reglas_set)
                    reglas_separadas=listanueva #se contruye nueva lista con el objetivo de eliminar los duplicados en la busqueda
                    
                    recorrer=0
                    for regla in reglas_separadas:
                        #print (reglas_separadas[recorrer])
                        try:
                            con=bbddsqlite3.sql_connection()
                            cursorObj = con.cursor()
                            aux=True
                        except Exception as e1:
                            return json.dumps({'status': 'fail', 'results': 'error de BBDD'}), status.HTTP_400_BAD_REQUEST
                        if aux:
                            try:
                                
                                resultado=cursorObj.execute("select id,nombre_regla,regla from reglas_yara where id = ?",(reglas_separadas[recorrer]))
                                data=resultado.fetchall()
                                aux=True
                            except Exception:
                                json_output=({reglas_separadas[recorrer]:" regla no encontrada"})
                                salida.append(json_output)
                                aux=False
                        
                        if aux:                            
                            if len(data)>0: 
                                for row in data:
                                    print(row)
                                    json_output = json.dumps(row)
                                    print(json_output)
                                    #salida.append(json_output)
                                    salida.append(row)
                                aux=True
                                                        
                        con.commit()
                        con.close()
                        aux=True
                        
           
                        recorrer=recorrer+1
                        #salida.append(json_output)
        
            
            return (json.dumps(salida))
        except Exception:
            return json.dumps({'status': 'fail', 'results': []}), status.HTTP_400_BAD_REQUEST
            

        
            
    except Exception as e:
        print(str(e))
        return json.dumps({'status': 'fail', 'results': []}), status.HTTP_400_BAD_REQUEST



@app.route('/api/yarapan', methods=['POST'])
def yarapan():
    #$fecha_creacion=/^\d{4}([\-.])(0?[1-9]|1[1-2])\1(3[01]|[12][0-9]|0?[1-9])$/
    #regla = yara.compile (source='rule foo: bar {strings: $token="TOKEN_" $fecha_creacion=/^\d{4}([\-.])(0?[1-9]|1[1-2])\1(3[01]|[12][0-9]|0?[1-9])$/  condition: $token and $fecha_creacion }')
    ##regla = yara.compile(sources = {'n' : 'rule r1 {strings: $anio_creacion = /^\d{4}([-])(0?[1-9]|1[1-2])([-])(3[01]|[12][0-9]|0?[1-9])$/ condition: $anio_creacion }' })    ##FECHA LISTA

    regla = yara.compile(sources = {'n' : 'rule r1 {strings: $anio_creacion = /(201[6-9]|202[0-2])([-])((0[13578]|1[02])([-])(31))|(201[6-9]|202[0-2])([-])((0[1,3-9]|1[0-2])([-])(29|30))|(201[6-9]|202[0-2])([-])(0[1-9]|1[0-2])([-])((28))|(201[6-9]|202[0-2])([-])(0[1-9]|1[0-2])([-])(([0][1-9])|([1][0-9])|([2][0-8]))/ condition: $anio_creacion }' })    ##FECHA LISTA


    ##regla = yara.compile(source='rule foo: bar {strings: $token=TOKEN_ $caracter=- $usuario=/d{6}/ condition: $token and ($caracter and $usuario)}') ##6DIGITOS
    #(0[1-9]|1[0-2]) MES
    ###(201[6-9]|202[0-2])([-])((0[13578]|1[02])([-])(31))|(201[6-9]|202[0-2])([-])((0[1,3-9]|1[0-2])([-])(29|30))|(201[6-9]|202[0-2])([-])(0[1-9]|1[0-2])([-])((28))|(201[6-9]|202[0-2])([-])(0[1-9]|1[0-2])([-])(([0][1-9])|([1][0-9])|([2][0-8]))
    
    #Fecha desde 31 de enero de 2016
    ##((201[6])([-])((0[3578]|1[02])([-])(31))|(201[6])([-])((0[3-9]|1[0-2])([-])(29|30))|(201[6])([-])(0[2-9]|1[0-2])([-])((28))|(201[6])([-])(0[2-9]|1[0-2])([-])(([0][1-9])|([1][0-9])|([2][0-8])))|(201[7-9]|202[0-2])([-])((0[13578]|1[02])([-])(31))|(201[7-9]|202[0-2])([-])((0[1,3-9]|1[0-2])([-])(29|30))|(201[7-9]|202[0-2])([-])(0[1-9]|1[0-2])([-])((28))|(201[7-9]|202[0-2])([-])(0[1-9]|1[0-2])([-])(([0][1-9])|([1][0-9])|([2][0-8]))
    
    #(201[6-9]|202[0-2])([-])((0[13578]|1[02])([-])(31))|(201[6-9]|202[0-2])([-])((0[1,3-9]|1[0-2])([-])(29|30))|(201[6-9]|202[0-2])([-])(0[1-9]|1[0-2])([-])((28))|(201[6-9]|202[0-2])([-])(0[1-9]|1[0-2])([-])(0[0-2]|1[0-9])
    ##regla = yara.compile(sources = {'n' : 'rule r1 {strings: $anio_creacion = /TOKEN([_])\d{4}([-])(0?[1-9]|1[1-2])([-])(3[01]|[12][0-9]|0?[1-9])([_])\d{6}$/ condition: $anio_creacion }' }) ##access_token
    
    ##regla = yara.compile(sources = {'n' : 'rule r1 { strings: $digitos= /^\d{6}$/ condition: $digitos}' })
    
    #regla = yara.compile(source='rule foo: bar {strings: $token=TOKEN_ $caracter=- $usuario=/d{6}/ condition: $token and ($caracter and $usuario)}')
    record = json.loads(request.data)
    print(record["access_token"])
    # revisar=str(record["text"])
    # print(type(revisar))


    #######TC 
    # VISA (\D|^)4[0-9]{3}(\ |\-|_)?+[0-9]{4}(\ |\-|_)?+[0-9]{4}(\ |\-|_)?+[0-9]{4}(\D|$)

    matches = regla.match(data=record["access_token"])
    print(len(matches))
    return json.dumps(matches),status.HTTP_200_OK
    

@app.route('/api/idusuario', methods=['POST'])
def idusuario():
    
    regla = yara.compile(sources = {'n' : 'rule r1 { strings: $digitos= /^\d{6}$/ condition: $digitos}' })

    record = json.loads(request.data)
    print(record["idusuario"])
        
    matches = regla.match(data=record["idusuario"])
    print(matches)
    return json.dumps(matches),status.HTTP_200_OK



app.run(debug=True)
