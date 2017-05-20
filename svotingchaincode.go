package main
import (
	"errors"
	"fmt"
	"github.com/hyperledger/fabric/core/chaincode/shim"
	"crypto/hmac"
	"encoding/pem"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"crypto/md5"
  "crypto/sha256"
  "encoding/hex"
  "io"
  "strings"
)
type Message struct {
    GroupID string
    QuestionID string
    Type string
    EtM string
    PublicKey []byte
    Cipher string
}
type ChoiceMsg struct {
	Name string
	Choice []byte
}
type svotingchaincode struct { }
func (t *svotingchaincode) Init(stub shim.ChaincodeStubInterface, data string, myKey []string) ([]byte, error) { 
		var logger = shim.NewLogger("test")
		fmt.Printf("rrrrrrrr")

		if myKey[0] == "get" {
			logger.Info("getgetgetget called");
			fmt.Printf("getetetetetet")
    }
		var msg []Message
		var groupId,questionId,etm,cipher string
		var pubkey,ciptext,cipherArr []byte
		var err error
		bytes := []byte(data)
    json.Unmarshal(bytes, &msg)
    keyarray := "\x00" + strings.Join(myKey,"\x20\x00")
		for _, data := range msg{
			groupId = data.GroupID
			questionId = data.QuestionID
			// typ = data.Type
			pubkey = data.PublicKey
			etm = data.EtM
			cipher = data.Cipher
		}
		fmt.Printf("getetetetetet"+groupId+questionId)
		logger.Info("data in inift:"+groupId+questionId)
		queryKey,_ := EncryptCipher(questionId,groupId,pubkey)
		squeryKey := fmt.Sprint(queryKey) // [1 2 3 4]

		RequestBytes, err := stub.GetState(squeryKey)
		if err != nil{
				return nil, errors.New("Failed to get states")
		}
		if RequestBytes != nil{
				return nil, errors.New("This person has voted")
		}
		//if CheckMAC(etm,cipher,myKey){//0 false
		hmac256 := ComputeHmac256(cipher,[]byte(keyarray))
		if hmac256 == etm{
			ciptext = append(ciptext,cipher...)					
			decipher,_ := DecryptCipher(ciptext,pubkey)
				if decipher != nil {
						err = stub.PutState(squeryKey,ciptext)
						if err != nil {
                				return nil, err
        				}
        				cipherArr = append(cipherArr,queryKey...)
        				md5res,_ := md5RecKey(questionId,groupId)
        				smd5res := fmt.Sprint(md5res)
 
        				err = stub.PutState(smd5res,cipherArr)
						if err != nil {
                				return nil, err
        				}
					}else{
						return nil, errors.New("Error encrypt key")
					}
			} else{
				return nil, errors.New("unmatch HMAC")	
			}
		return nil,nil
}
func (t *svotingchaincode) Invoke(stub shim.ChaincodeStubInterface, data string, myKey []string) ([]byte, error) {
		// if function == "delete" {
  //               // Deletes an entity from its state
  //               return t.delete(stub, args)
  //       }//why need it
	    var msg []Message
		var groupId,questionId,etm,cipher string
		var pubkey,ciptext,cipherArr []byte
		var err error
		bytes := []byte(data)
    	json.Unmarshal(bytes, &msg)
		keyarray := "\x00" + strings.Join(myKey,"\x20\x00")

		for _, data := range msg{
			groupId = data.GroupID
			questionId = data.QuestionID
			// typ = data.Type
			pubkey = data.PublicKey
			etm = data.EtM
			cipher = data.Cipher
		}
		queryKey,_ := EncryptCipher(questionId,groupId,pubkey)
		squeryKey := fmt.Sprint(queryKey) // [1 2 3 4]

		RequestBytes, err := stub.GetState(squeryKey)
		if err != nil{
				return nil, errors.New("Failed to get states")
		}
		if RequestBytes == nil {
			return nil, errors.New("Entity not found")
		}
		hmac256 := ComputeHmac256(cipher,[]byte(keyarray))
		if hmac256 == etm{//if CheckMAC(etm,cipher,myKey){//0 false
			ciptext = append(ciptext,cipher...)
			decipher,_ := DecryptCipher(ciptext,pubkey)			
				if decipher != nil {
						err = stub.PutState(squeryKey,ciptext)
						if err != nil {
                				return nil, err
        				}
        				cipherArr = append(cipherArr,queryKey...)
        				md5res,_ := md5RecKey(questionId,groupId)
        				smd5res := fmt.Sprint(md5res)

        				err = stub.PutState(smd5res,cipherArr)

						if err != nil {
                				return nil, err
        				}
					}else{
						return nil, errors.New("Error encrypt key")
					}
			} else{
				return nil, errors.New("UnMatch HMAC")	
			}
		return nil,nil

}
func (t *svotingchaincode) Query(stub shim.ChaincodeStubInterface, function string, args []string) ([]byte, error) {
		if function != "query" {
                return nil, errors.New("Invalid query function name. Expecting \"query\"")
        }
		var returnArr []byte
   		md5res,_ := md5RecKey(args[0],args[1])
        smd5res := fmt.Sprint(md5res)
        
        qkeydata := []byte{}
		qkeydata = append(qkeydata, args[3]...)

       // if isdata == false{//only counting
        		var resArr []int
        		

		        Resultbytes, err := stub.GetState(smd5res)
		        if err != nil{
		                jsonResp := "Failed to get state for " + args[0] +"-"+args[1] + "\"}"
		                return nil, errors.New(jsonResp)        	
		        }
		        
		        if Resultbytes == nil{
		                jsonResp := "Nil entity for " + args[0] +"-"+args[1] + "\"}"
		                return nil, errors.New(jsonResp)        	
		        }

				for _, res := range Resultbytes {
	                //gte res to query the cipher
        			sres := fmt.Sprint(res)

	                datas,_ := stub.GetState(sres)
	                // sdatas := fmt.Sprint(datas)
	                ori,_ := DecryptCipher(datas,qkeydata)

	                var choicemsg []ChoiceMsg
	                cmsg := []byte(ori)
    				json.Unmarshal(cmsg, &choicemsg)
			
	               
	                for i := 0; i < len(choicemsg); i ++ {
					    resArr[i] ++
					}

        		}		
                for i := 0; i < len(resArr); i ++ {
				    //copy(returnArr[i], strconv.Itoa(resArr[i]))
				    returnArr[i] = byte(resArr[i])
				}
		        return returnArr, nil        		

}
func ComputeHmac256(message string, key []byte) string {
    // key := []byte(secret)
    h := hmac.New(sha256.New, key)
    h.Write([]byte(message))
    return hex.EncodeToString(h.Sum(nil))
}

func EncryptCipher(qid string,gid string,key []byte) ([]byte, error) {
	origData := []byte(qid)
	origData = append(origData, gid...)
    block, _ := pem.Decode(key)
    if block == nil {
        return nil, errors.New("EncryptCipher key error")
    }
    pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
    if err != nil {
        return nil, err
    }
    pub := pubInterface.(*rsa.PublicKey)
    return rsa.EncryptPKCS1v15(rand.Reader, pub, origData)
}
//decrypt to get person and choice
func DecryptCipher(ciphertext []byte, key []byte) ([]byte, error){
	block, _ := pem.Decode(key)
	if block == nil {
		return nil, errors.New("DecryptCipher key error!")
	}
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return rsa.DecryptPKCS1v15(rand.Reader, priv, ciphertext)
}

//hash gid and qid
func md5CipKey(qid string,gid string,personkey []byte) ([]byte, error){
	h := md5.New()
	io.WriteString(h,qid)
	io.WriteString(h, gid)
	skey := fmt.Sprint(personkey) // [1 2 3 4]
	io.WriteString(h, skey)
	fmt.Printf("%x\n", h.Sum(nil))
	return h.Sum(nil), nil
}
func md5RecKey(qid string,gid string) ([]byte, error){
	h := md5.New()
	io.WriteString(h,qid)
	io.WriteString(h, gid)
	fmt.Printf("%x\n", h.Sum(nil))
	return h.Sum(nil), nil
}
func main() {
        err := shim.Start(new(svotingchaincode))
        if err != nil {
                fmt.Printf("Error starting chaincode: %s", err)
        }
}
