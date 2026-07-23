
#Область РаботаCКорзинойS3


#Область HMAC_SHA256


Функция Hash(BinaryData, Type)
	
	HashingObj = New DataHashing(Type);
	HashingObj.Append(BinaryData);
	
	Return HashingObj.HashSum;
		
КонецФункции   

Функция HashFromFile(FileName, Type)
	
	HashingObj = New DataHashing(Type);
	HashingObj.AppendFile(FileName);
	
	Return HashingObj.HashSum;
		
КонецФункции  

Функция HashFromData(Data, Type)
	
	HashingObj = New DataHashing(Type);
	HashingObj.Append(Data);
	
	Return HashingObj.HashSum;
		
КонецФункции  

Функция HMAC(Val KeyValue, Val Data, Type, BlockSize)
	
	If KeyValue.Size() > BlockSize Тогда
		KeyValue = Hash(KeyValue, Type);
	КонецЕсли;
	
	If KeyValue.Size() < BlockSize Тогда
		KeyValue = GetHexStringFromBinaryData(KeyValue);
		KeyValue = Left(KeyValue + RepeatString("00", BlockSize), BlockSize * 2);
	КонецЕсли;
	
	KeyValue = GetBinaryDataBufferFromBinaryData(GetBinaryDataFromHexString(KeyValue));
	
	ipad = GetBinaryDataBufferFromHexString(RepeatString("36", BlockSize));
	opad = GetBinaryDataBufferFromHexString(RepeatString("5c", BlockSize));
	
	ipad.WriteBitwiseXor(0, KeyValue);
	ikeypad = GetBinaryDataFromBinaryDataBuffer(ipad);
	
	opad.WriteBitwiseXor(0, KeyValue);
	okeypad = GetBinaryDataFromBinaryDataBuffer(opad);
	
	Return Hash(CombineBinaryData(okeypad, Hash(CombineBinaryData(ikeypad, Data), Type)), Type);
	
КонецФункции

Функция CombineBinaryData(BinaryData1, BinaryData2)
	
	BinaryArray = New Array;
	BinaryArray.Add(BinaryData1);
	BinaryArray.Add(BinaryData2);
	
	Return ConcatBinaryData(BinaryArray);
	
КонецФункции

Функция RepeatString(String, Count)
	
	Parts = New Array(Count);
	For i = 1 To Count Do
		Parts.Add(String);
	EndDo;
	
	Return StrConcat(Parts, "");
	
КонецФункции    

Функция HMACSHA256(Val Key, Val Data)
	
	Return HMAC(Key, Data, HashFunction.SHA256, 64);
	
КонецФункции
              
Функция GetSignatureKey(key, dateStamp, regionName, serviceName) 
	
	kSecret 	= GetBinaryDataFromString("AWS4" + key);	     
	kDate 		= HMACSHA256(kSecret, 	GetBinaryDataFromString(dateStamp));
	kRegion 	= HMACSHA256(kDate, 	GetBinaryDataFromString(regionName));
	kService 	= HMACSHA256(kRegion, 	GetBinaryDataFromString(serviceName));
	kSigning 	= HMACSHA256(kService, 	GetBinaryDataFromString("aws4_request"));

    Return kSigning; 
	
КонецФункции   


#КонецОбласти

#Region AWS_Request


Процедура РазобратьОтветXml(ResponseText)   
	
	ЭтотОбъект.BucketObjects.Clear();   
	
	ЧтениеXML = New ЧтениеXML;
	ЧтениеXML.УстановитьСтроку(ResponseText); 
	
	Obj = ФабрикаXDTO.ПрочитатьXML(ЧтениеXML);   
	
	ЭтотОбъект.m_IsTruncated = Булево(Obj.IsTruncated);    	
	Если ЭтотОбъект.m_IsTruncated Тогда
		ЭтотОбъект.m_NextContinuationToken = Obj.NextContinuationToken;
	Иначе 
		ЭтотОбъект.m_NextContinuationToken = "";
	КонецЕсли;           
	
	Если TypeOf(Obj.Prefix) = Type("String") Тогда 
		ЭтотОбъект.m_Prefix = Obj.Prefix;        
	Иначе
		ЭтотОбъект.m_Prefix = ""
	КонецЕсли;
	
	Если Not Obj.Properties().Get("CommonPrefixes") = Undefined Тогда   
		CommonPrefixes = Obj.CommonPrefixes;
		Если ТипЗнч(CommonPrefixes) = Тип("XDTODataObject") Тогда
			мПрефиксов = Новый Массив;
			мПрефиксов.Добавить(CommonPrefixes);
		Иначе 
			мПрефиксов = CommonPrefixes;
		КонецЕсли;	  
		
		Для Каждого CommonPrefix Из мПрефиксов Цикл    
			СтрокаО = ЭтотОбъект.BucketObjects.Add();  
			СтрокаО.isFolder 		=  Истина;
			СтрокаО.Key 			= CommonPrefix.Prefix;
			СтрокаО.ObjectShortName = Mid(CommonPrefix.Prefix, StrLen(ЭтотОбъект.m_Prefix) + 1);
		КонецЦикла;  
	КонецЕсли;
	
	Если Obj.Properties().Get("Contents") <> Неопределено Тогда  
		
		Если ТипЗнч(Obj.Contents) = Тип("XDTODataObject") Тогда   
			мОбъектов = Новый Массив;
			мОбъектов.Add(Obj.Contents);
		Иначе 
			мОбъектов = Obj.Contents;
		КонецЕсли;	  
		
		Для каждого Content Из мОбъектов Цикл		
			СтрокаО = ЭтотОбъект.BucketObjects.Add();  
			
			СтрокаО.isFolder 		= False;
			
			СтрокаО.Key 			= Content.Key;
			СтрокаО.LastModified 	= XMLValue(Type("Date"), Content.LastModified);
			СтрокаО.ETag 			= Content.ETag;
			СтрокаО.Size 			= Content.Size;
			СтрокаО.StorageClass 	= Content.StorageClass;
			СтрокаО.ObjectShortName = Mid(Content.Key, StrLen(ЭтотОбъект.m_Prefix) + 1);  
		EndDo;			
		
	КонецЕсли;          
	
	ЭтотОбъект.BucketObjects.Sort("isFolder DESC, Key");
	
КонецПроцедуры

Процедура ПолучитьСписокФайлов(Корзина, Префикс="", пОбработки = Неопределено) Экспорт	
	Если ТипЗнч(пОбработки) <> Тип("Структура") Тогда
		пОбработки = Новый Структура;		
	КонецЕсли; 
	пОбработки.Вставить("Корзина", Корзина);
	
	рВыполнения = ВыполнитьКомандуS3("ListFiles", Префикс, пОбработки);	
	Если рВыполнения.Успешно Тогда
	Иначе
		Сообщить(СтрСоединить(рВыполнения.Ошибки, СтатусСообщения.Важное));	
	КонецЕсли; 
КонецПроцедуры	

Процедура СоздатьПапку(ИмяПапки) Экспорт        
	
	Префикс = StrReplace(EncodeString(ЭтотОбъект.m_Prefix + ИмяПапки + "/", StringEncodingMethod.URLEncoding), "%2F", "/");	

	ВыполнитьКомандуS3("UploadFile", Префикс);	
	
КонецПроцедуры  

Функция ПоместитьДанныеВКорзину(ДД, Корзина, ИсходноеИмяФайла) Экспорт	
	Файл 	= Новый Файл(ИсходноеИмяФайла);
	
	ИмяФайла	= Файл.Имя;	
	Префикс		= СтрЗаменить(КодироватьСтроку(ЭтотОбъект.m_Prefix + ИмяФайла, СпособКодированияСтроки.КодировкаURL), "%2F", "/");	
	
	ContentType = "application/octet-stream";
	If СтрЗаканчиваетсяНа(ИмяФайла, ".jpg") Тогда   
		ContentType = "image/jpeg";
	КонецЕсли;
	
	пКоманды = Новый Структура("Корзина,ContentType,data", Корзина, ContentType, ДД);
	
	Возврат ВыполнитьКомандуS3("UploadFile", Префикс, пКоманды);	
КонецФункции

Функция ПрочитатьФайлИзКорзины(ИмяФайла) Экспорт	
	Префикс		= СтрЗаменить(КодироватьСтроку(ИмяФайла, СпособКодированияСтроки.КодировкаURL), "%2F", "/");
	Возврат ВыполнитьКомандуS3("DownloadFile", Префикс);	
КонецФункции

Функция ВыполнитьКомандуS3(Command, CurrentPrefix, ДопПараметры = Неопределено) Экспорт 
	Результат = Новый Структура("Успешно,Ошибки,Сообщения,Данные", Истина, Новый Массив, Новый Массив, Неопределено);
	
	пПодключения = ПолучитьПараметрыПодключенияS3();
	
	Host		= пПодключения.Host;
	Port		= пПодключения.Port;
	UseSSL		= пПодключения.UseSSL;	
	
	AccessKey	= пПодключения.AccessKey;
	SecretKey	= пПодключения.SecretKey;
	
	Region		= пПодключения.Region;	
	
	Service		= "s3";
	
	Корзина				= ПолучитьЗначениеПараметра(ДопПараметры, "Корзина", "");
	MaxKeysPerRequest	= ПолучитьЗначениеПараметра(ДопПараметры, "MaxKeysPerRequest", 1000);
	
	AbsolutePath = "/" + Корзина + "/";
	
	contentHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"; //empty string       
	contentType = ""; //"text/plain";           
	verb 		= "GET";      
	
	Prefix 		  = StrReplace(EncodeString(CurrentPrefix, StringEncodingMethod.URLEncoding), "%2F", "/");  
	PrefixEncoded = EncodeString(CurrentPrefix, StringEncodingMethod.URLEncoding);  
	
	queryParams = "delimiter=%2F&list-type=2&max-keys=" + ЧислоБезДури(MaxKeysPerRequest) + "&prefix=" + PrefixEncoded;   
	
	uri = AbsolutePath  + "?delimiter=/&list-type=2&max-keys=" + ЧислоБезДури(MaxKeysPerRequest) + "&prefix=" + Prefix;       
	
	РазмерДанных = 0;
	
	data = Неопределено;
	Если Command = "UploadFile" Тогда   
		
		verb 			= "PUT";    
		queryParams 	= "";    
		uri				= AbsolutePath + CurrentPrefix;    
		AbsolutePath 	= uri;
		
		contentType		= ПолучитьЗначениеПараметра(ДопПараметры, "contentType", "");
		data			= ПолучитьЗначениеПараметра(ДопПараметры, "data");		
		
		РазмерДанных	= data.Размер();
		
		Если data <> Неопределено Тогда
			contentHash = Lower(GetHexStringFromBinaryData(HashFromData(data, HashFunction.SHA256)));	  
		КонецЕсли;   
		
	ИначеЕсли Command = "DeleteFile" Тогда
		
		verb 			= "DELETE";    
		queryParams 	= "";    
		uri				= AbsolutePath + CurrentPrefix;    
		AbsolutePath 	= uri; 
		
	ИначеЕсли Command = "DownloadFile" Тогда
		
		verb 			= "GET";    
		queryParams 	= "";    
		uri				= AbsolutePath + CurrentPrefix;    
		AbsolutePath 	= uri; 
		
	КонецЕсли;
	
	date 	  = Format(CurrentUniversalDate(), "DF=yyyyMMddTHHmmssZ");
	dateStamp = Format(CurrentUniversalDate(), "DF=yyyyMMdd");   
	
	scope = dateStamp + "/" + Region + "/" + Service + "/aws4_request";    
	
	NewLine = Chars.LF;     
	
	canonicalRequestPlain = verb + NewLine +
		AbsolutePath + NewLine +
		queryParams + NewLine +		
		"host:" + Host + NewLine  +
		"x-amz-content-sha256:" + contentHash + NewLine  +
		"x-amz-date:" + date + NewLine + 
		NewLine +
		"host;x-amz-content-sha256;x-amz-date" + NewLine +
		"" + contentHash;
		
	canonicalRequestByte = Hash(canonicalRequestPlain, ХешФункция.SHA256);    
	
	canonicalRequestHash = Lower(GetHexStringFromBinaryData(canonicalRequestByte)); 
	
	stringToSign = "AWS4-HMAC-SHA256" + NewLine + date + NewLine + scope + NewLine + canonicalRequestHash;	
	
	sign = GetSignatureKey(SecretKey, dateStamp, Region, Service);
	
	signatureByte = HMACSHA256(sign, GetBinaryDataFromString(stringToSign));   
	
	signatureHash = Lower(GetHexStringFromBinaryData(signatureByte));
	
	Authorization = "AWS4-HMAC-SHA256 Credential=" + AccessKey + "/" + scope 
		+ ",SignedHeaders=host;x-amz-content-sha256;x-amz-date,Signature=" + signatureHash;
	
	headers = Новый  Соответствие();
	headers.Insert("host", 					Host);	
	headers.Insert("x-amz-content-sha256", 	contentHash);
	headers.Insert("x-amz-date", 			date);
	headers.Insert("Authorization", 		Authorization);     
	
	HTTP_Запрос = Новый HTTPЗапрос(uri, headers);     
	Если data <> Неопределено Тогда
		HTTP_Запрос.УстановитьТелоИзДвоичныхДанных(data);		
	КонецЕсли;
	
	Если UseSSL Тогда	
		Connection = New HTTPConnection(Host, Port,,,,, New OpenSSLSecureConnection);  	
	Иначе
		Connection = New HTTPConnection(Host, Port);  	
	КонецЕсли;
	
	Result = Connection.CallHTTPMethod(verb, HTTP_Запрос);    

	RequestText = canonicalRequestPlain;
		
	Если Result.StatusCode = 200 
		OR Result.StatusCode = 204 Тогда 
		
		Если Command = "DownloadFile" Тогда
			Результат.Данные 	= Result.ПолучитьТелоКакДвоичныеДанные();			
			РазмерДанных    	= Результат.Данные.Размер();
		Иначе	
			ResponseText = Result.GetBodyAsString();  			
			Если ЗначениеЗаполнено(ResponseText) Тогда
				РазобратьОтветXml(ResponseText);        
			КонецЕсли;
		КонецЕсли;		
	Иначе       
		
		ResponseText = Result.GetBodyAsString();  
		
		ТекстОшибки = СтрШаблон("The request has failed with the status code: '%1' !
		| response tect: '%2'.", 
			Result.StatusCode,
			ResponseText
		);
		
		Результат.Ошибки.Добавить(ТекстОшибки);		
		
		//Items.GroupPages.CurrentPage = items.GroupRequestLog;		
	КонецЕсли;
	
	Результат.Вставить("РазмерДанных", РазмерДанных);
	Результат.Успешно = (Результат.Ошибки.Количество()=0);
	Результат.Сообщения.Добавить(СтрШаблон("Сервер получатель: %1, корзина: %2.", Host, Корзина));
	
	Возврат Результат;	
КонецФункции


#EndRegion

#Область ПараметрыПодключения


Функция ПолучитьПараметрыПодключенияS3()	
	Возврат ?(фОтладка, ПараметрыПодключенияS3_Отладка(), ПараметрыПодключенияS3_Рабочие());
КонецФункции // ()

Функция ПараметрыПодключенияS3_Отладка()
	пПодключения = Новый  Структура;
	
	пПодключения.Вставить("Host",		"Chirkov");
	пПодключения.Вставить("Port",		9000);
	пПодключения.Вставить("UseSSL",	 	Ложь);	
	пПодключения.Вставить("Service",	"s3");
	
	пПодключения.Вставить("AccessKey",	"Admin");
	пПодключения.Вставить("SecretKey",	"Password");
	
	пПодключения.Вставить("Region",		"eu-central-1");	
	
	Возврат пПодключения;
КонецФункции // ()

Функция ПараметрыПодключенияS3_Рабочие()
	пПодключения = Новый  Структура;
	
	пПодключения.Вставить("Host",		"hb.bizmrg.com");
	пПодключения.Вставить("Port",		443);
	пПодключения.Вставить("UseSSL",	 	Истина);	
	пПодключения.Вставить("Service",	"s3");
	
	пПодключения.Вставить("AccessKey",	"68Gj9WmQnn6dy3M1f1Kdf7");
	пПодключения.Вставить("SecretKey",	"idLjBxyiesadXTHBv7RSkhcpW279QKVKLUGHCeWYkSdw");
	
	пПодключения.Вставить("Region",		"eu-central-1");	
	
	Возврат пПодключения;
КонецФункции // ()


#КонецОбласти


#КонецОбласти


#Область Остатки


Функция ПрочитатьОстатки(ДД) Экспорт
	Результат = Новый Структура("Успешно,Ошибки,Сообщения,Данные", Истина, Новый Массив, Новый Массив, Неопределено);
	
	СовсемНачало = ТекущаяУниверсальнаяДатаВМиллисекундах();
	
	Начало = ТекущаяУниверсальнаяДатаВМиллисекундах();	
	
	ХЗ = ЗначениеИзСтрокиВнутр(ПолучитьСтрокуИзДвоичныхДанных(ДД));	
	ТО = ХЗ.Получить();
	
	Время = (ТекущаяУниверсальнаяДатаВМиллисекундах() - Начало)/1000;	
	ВсегоСтрок = ТО.Количество();	
	ТекстСообщения = СтрШаблон("Чтение из файла. Прочитано %1 строк, время: %2 с, скорость: %3 стр/с.",
		ВсегоСтрок, Время, Формат( ВсегоСтрок/Время, "ЧДЦ=0; ЧРГ=' '; ЧГ=3,0")
	);
	Результат.Сообщения.Добавить(ТекстСообщения);
	
	ТО.Колонки.Добавить("Склад");
	ТО.Колонки.Добавить("Номенклатура");
	ТО.Колонки.Добавить("ХарактеристикаНоменклатуры");
	
	Начало = ТекущаяУниверсальнаяДатаВМиллисекундах();
	
	КэшСкладов = Новый Соответствие;
	
	Для Каждого СтрокаТО Из ТО Цикл
		Склад = КэшСкладов.Получить(СтрокаТО.СкладУИД);
		Если Склад = Неопределено Тогда
			Склад = Справочники.Склады.ПолучитьСсылку(СтрокаТО.СкладУИД);		
			КэшСкладов.Вставить(СтрокаТО.СкладУИД, Склад);
		КонецЕсли; 
		СтрокаТО.Склад = Склад;	
		СтрокаТО.ХарактеристикаНоменклатуры = Справочники.ХарактеристикиНоменклатуры.ПолучитьСсылку(СтрокаТО.НоменклатураУИД);	
	КонецЦикла; 
	
	Время = (ТекущаяУниверсальнаяДатаВМиллисекундах() - Начало)/1000;	
	
	Результат.Сообщения.Добавить("Восстановление ссылок. Обработано "+ВсегоСтрок+" строк, время: "+Время+" с, скорость: "+Формат( ВсегоСтрок/Время, "ЧДЦ=0; ЧРГ=' '; ЧГ=3,0")+" стр/с.");
	
	Время = (ТекущаяУниверсальнаяДатаВМиллисекундах() - СовсемНачало)/1000;
	
	ТО.Колонки.Удалить("НоменклатураУИД");
	ТО.Колонки.Удалить("СкладУИД");		
	
	Результат.Сообщения.Добавить("Общее время распаковки данных: "+Время+" с.");
	Результат.Сообщения.Добавить("=============================================");
	
	Результат.Данные = ТО;
	
	Возврат Результат;
КонецФункции //ПрочитатьОстатки(ДД)


#Область ВыгрузкаОстатков


Функция ВыгрузитьОстаткиВКорзину() Экспорт
	Возврат ПоместитьДанныеВКорзину(ВыгрузитьОстатки(), ИмяКорзины(), "Остатки SNL.dat");	
КонецФункции

Функция ВыгрузитьОстатки(ИмяФайла = "")
	СовсемНачало = ТекущаяУниверсальнаяДатаВМиллисекундах();
	
	Запрос = Новый Запрос;
	Запрос.Текст = "
	|ВЫБРАТЬ
	|	Склад,
	|	Номенклатура,
	|	КоличествоОстаток КАК КолКонЕЕ
	|ИЗ
	|	РегистрНакопления.ОстаткиТМЦ.Остатки(, Склад В (&СписокСкладов))
	|";
	
	СписокСкладов = Новый Массив;
	СписокСкладов.Добавить(Справочники.Склады.НайтиПоКоду("STA-48")); //Склад Часцы (Основной)
	СписокСкладов.Добавить(Справочники.Склады.НайтиПоКоду("STB-01")); //Склад Часцы (Франчайзинг)	
	
	Запрос.УстановитьПараметр("СписокСкладов", СписокСкладов);
	
	Начало = ТекущаяУниверсальнаяДатаВМиллисекундах();
	
	Результат 	= Запрос.Выполнить();
	ТО			= Результат.Выгрузить();
	
	Время = (ТекущаяУниверсальнаяДатаВМиллисекундах() - Начало)/1000;
	
	ВсегоСтрок = ТО.Количество();	
	Сообщить("Чтение из базы. Прочитано "+ВсегоСтрок+" строк, время: "+Время+" с, скорость: "+Формат( ВсегоСтрок/Время, "ЧДЦ=0; ЧРГ=' '; ЧГ=3,0")+" стр/с.");
	
	ТО.Колонки.Добавить("НоменклатураУИД", Новый ОписаниеТипов("УникальныйИдентификатор"));
	ТО.Колонки.Добавить("СкладУИД", Новый ОписаниеТипов("УникальныйИдентификатор"));
	
	Начало = ТекущаяУниверсальнаяДатаВМиллисекундах();
	
	Для Каждого СтрокаТО Из ТО Цикл
		СтрокаТО.СкладУИД 			= СтрокаТО.Склад.УникальныйИдентификатор();
		СтрокаТО.НоменклатураУИД 	= СтрокаТО.Номенклатура.УникальныйИдентификатор();
	КонецЦикла; 
	
	Время = (ТекущаяУниверсальнаяДатаВМиллисекундах() - Начало)/1000;
	
	Сообщить("Запись ИД. Записано "+ВсегоСтрок +", время: " +Время+" с, скорость: " + Формат( ВсегоСтрок/Время, "ЧДЦ=0; ЧРГ=' '; ЧГ=3,0") + " стр/с.");
	
	ТО.Колонки.Удалить("Номенклатура");
	ТО.Колонки.Удалить("Склад");	
	
	Данные = Новый Структура("ДатаФормирования,Остатки", ТекущаяДата(), ТО);
	
	Начало = ТекущаяУниверсальнаяДатаВМиллисекундах();
	
	ХЗ	= Новый ХранилищеЗначения(Данные, Новый СжатиеДанных(9));	
	ДД	= ПолучитьДвоичныеДанныеИзСтроки(ЗначениеВСтрокуВнутр(ХЗ));
	Если ЗначениеЗаполнено(ИмяФайла) Тогда	
		ДД.Записать(ИмяФайла);	
	КонецЕсли; 	
	
	Время = (ТекущаяУниверсальнаяДатаВМиллисекундах() - Начало)/1000;
	
	Сообщить("Запись в файл. Записано "+ВсегоСтрок +" строк, время: " +Время+" с, скорость: " + Формат( ВсегоСтрок/Время, "ЧДЦ=0; ЧРГ=' '; ЧГ=3,0") + " стр/с.");
	
	
	Время = (ТекущаяУниверсальнаяДатаВМиллисекундах() - СовсемНачало)/1000;	
	
	Сообщить("=============================================");
	Сообщить("Общее время подготовки данных: "+Время+" с, размер файла: "+Формат(ДД.Размер(), "ЧРГ=' '; ЧГ=3,0")+" байт.");	
	
	Возврат ДД;
КонецФункции


#КонецОбласти 

	
#КонецОбласти 


#Область Регламент
	
Функция ПолучитьПараметры() Экспорт
	ТП = Новый ТаблицаЗначений;
	ТП.Колонки.Добавить("Имя");
	ТП.Колонки.Добавить("Значение");
	
	СтрокаТП = ТП.Добавить(); СтрокаТП.Имя = "фОтладка"; 		СтрокаТП.Значение = Ложь;	
	
	Возврат ТП;
КонецФункции //ПолучитьПараметры() Экспорт

Функция Сформировать(тПараметры = Неопределено) Экспорт
	пОбработки = Новый Соответствие;
	Если ТипЗнч(тПараметры) = Тип("ТаблицаЗначений") Тогда
		Для Каждого СтрокаТП Из тПараметры Цикл
			пОбработки[СтрокаТП.Имя] = СтрокаТП.Значение;		
		КонецЦикла;
	КонецЕсли;
	
	Если пОбработки.Получить("фОтладка")<>Неопределено Тогда
		фОтладка = пОбработки["фОтладка"];
	КонецЕсли; 
	
	ИмяЛога = "Выгрузка остатков ЕЕ";
	ЗаписатьВЛог(ИмяЛога,"Начало", "Информация"); 
	
	Начало 		= ТекущаяУниверсальнаяДатаВМиллисекундах();
	
	рОтправки	= ВыгрузитьОстаткиВКорзину();	
	
	Если рОтправки.Успешно Тогда
		ТекстСообщения = СтрШаблон("Отправлено: %1 байт.",рОтправки.РазмерДанных);	
		ТипСообщения = "Информация";
	Иначе
		ТекстСообщения	= СтрСоединить(рОтправки.Ошибки, Символы.ПС);	
		ТипСообщения	= "Ошибка";		
	КонецЕсли;
	
	ТекстСообщения = ТекстСообщения+Символы.ПС+СтрСоединить(рОтправки.Сообщения, Символы.ПС);
	
	ВремяВыполнения = (ТекущаяУниверсальнаяДатаВМиллисекундах()-Начало)/1000;
	ЗаписатьВЛог(ИмяЛога,"Завершение. "+ТекстСообщения, ТипСообщения, , , ВремяВыполнения); 		
КонецФункции //Сформировать(ТаблицаПараметров = Неопределено) Экспорт


#КонецОбласти


#Область ВспомогательныеФункции


Функция ИмяКорзины() Экспорт
	Возврат "franchee";
КонецФункции // ()
 
Функция ЧислоБезДури(Значение)
	Возврат Формат(Значение, "ЧГ=");
КонецФункции //ЧислоБезДури(Значение)
 
Функция ПолучитьЗначениеПараметра(СтруктураПараметров,Имя,ЗначениеПоУмолчанию=Неопределено) Экспорт
	Результат	= ЗначениеПоУмолчанию;
	Если ТипЗнч(СтруктураПараметров)=Тип("Структура") Тогда
		ВремЗнач=Неопределено;
		Если СтруктураПараметров.Свойство(Имя,ВремЗнач) Тогда
			Результат	= ВремЗнач;		
		КонецЕсли; 
	ИначеЕсли ТипЗнч(СтруктураПараметров)=Тип("ДанныеФормыСтруктура") Тогда
		ВремЗнач=Неопределено;
		Если СтруктураПараметров.Свойство(Имя,ВремЗнач) Тогда
			Результат	= ВремЗнач;		
		КонецЕсли; 
	ИначеЕсли ТипЗнч(СтруктураПараметров)=Тип("Соответствие") Тогда
		ВремЗнач=СтруктураПараметров.Получить(Имя);
		Если ВремЗнач<>Неопределено Тогда
			Результат=ВремЗнач;		
		КонецЕсли;				
	КонецЕсли;
	Возврат Результат;
КонецФункции //ПолучитьЗначениеПараметра(СтруктураПараметров,Имя,ЗначениеПоУмолчанию=Неопределено) Экспорт


#КонецОбласти