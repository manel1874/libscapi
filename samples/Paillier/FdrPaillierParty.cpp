////
//// Created by liork on 25/04/16.
////
//
//#include "FdrPaillierParty.hpp"
//
//
//FdrPaillierParty::FdrPaillierParty(int partyId, char *inputFilePath, char *outputFilePath,int commPortNumber) :
//        FdrParty(partyId,inputFilePath,outputFilePath,commPortNumber)
//{
//    paillier_pubkey_t **pub = &m_paillierPub;
//    paillier_prvkey_t **prv = &m_paillierPrv;
//    m_paillier.paillier_keygen(2560, pub, prv, m_getRand);
//    m_multbyconst = 0;
//    m_addHomporphismCounter = 0;
//    m_decryptCounter = 0;
//    m_encryptCounter = 0;
//
//}
//
//FdrPaillierParty::~FdrPaillierParty()
//{
//    cout << "counters values are :"<<endl;
//    cout << "m_multbyconst value is : "<<m_multbyconst<<endl;
//    cout << "m_addHomporphismCounter value is : "<<m_addHomporphismCounter<<endl;
//    cout << "m_decryptCounter value is : "<<m_decryptCounter<<endl;
//    cout << "m_encryptCounter value is : "<<m_encryptCounter<<endl;
//}
//
//FdrPaillierParty1::FdrPaillierParty1(char *inputFilePath, char *outputFilePath, int commPortNumber) :
//        FdrPaillierParty(1,inputFilePath,outputFilePath,commPortNumber) { }
//
//
//FdrPaillierParty1::~FdrPaillierParty1()
//{ }
//
//void FdrPaillierParty1::run()
//{
//    mpz_t p;
//    mpz_t q;
//    char *copyStr = NULL;
//
//    while(read(p)==0 && read(q)==0)
//    {
//        mpz_class cp(p);
//        m_pCandidates.push_back(cp);
//        mpz_class cq(q);
//        m_qCandidates.push_back(cq);
//    }
//
//    for(int candidateIdx=0;candidateIdx<m_pCandidates.size();candidateIdx++)
//    {
//
//        // M represents message, message stores the multiplication result
//        paillier_plaintext_t *e1M = new paillier_plaintext_t();
//        paillier_ciphertext_t *e1 = new paillier_ciphertext_t();
//
//        mpz_init(e1M->m);
//        mpz_mul(e1M->m, m_pCandidates[candidateIdx].get_mpz_t(), m_qCandidates[candidateIdx].get_mpz_t());
//
//        e1 = m_paillier.paillier_enc(e1, m_paillierPub, e1M, m_getRand); // need to send e1.c
//        m_encryptCounter++;
//        //m_paillierIO.writeToFile(e1->c);
//        m_e1e2e3Vector.push_back(mpz_get_str(copyStr,10,e1->c));
//
//        paillier_plaintext_t *e2M = new paillier_plaintext_t();
//        paillier_ciphertext_t *e2 = new paillier_ciphertext_t();
//
//        mpz_init(e2M->m);
//        mpz_set(e2M->m, m_pCandidates[candidateIdx].get_mpz_t());
//
//        e2 = m_paillier.paillier_enc(e2, m_paillierPub, e2M, m_getRand);
//        m_encryptCounter++;
//        m_e1e2e3Vector.push_back(mpz_get_str(copyStr,10,e2->c));
//        //m_paillierIO.writeToFile(e2->c);
//
//        paillier_plaintext_t *e3M = new paillier_plaintext_t();
//        paillier_ciphertext_t *e3 = new paillier_ciphertext_t();
//
//        mpz_init(e3M->m);
//        mpz_set(e3M->m, m_qCandidates[candidateIdx].get_mpz_t());
//
//        e3 = m_paillier.paillier_enc(e3, m_paillierPub, e3M, m_getRand);
//        m_encryptCounter++;
//        //m_paillierIO.writeToFile(e3->c);
//        m_e1e2e3Vector.push_back(mpz_get_str(copyStr,10,e3->c));
//    }
//    send(m_e1e2e3Vector);
//    cout<<"element at idx 0 is : "<<m_e1e2e3Vector[0]<<endl;
//        //m_paillierIO.sendFile();
//
//        /*
//        vector<mpz_class> eVector;
//        vector<mpz_class> NVector;
//        mpz_t e;
//
//        while(m_paillierIO.readPaillier(e)==0)
//        {
//            mpz_class ce(e);
//            eVector.push_back(ce);
//        }
//
//        for(int candidateIdx=0;candidateIdx<eVector.size();candidateIdx++)
//        {
//            paillier_plaintext_t* N = new paillier_plaintext_t();
//            paillier_ciphertext_t* nFromSender = new paillier_ciphertext_t();
//            mpz_set(nFromSender->c,eVector[candidateIdx].get_mpz_t());
//            N = m_paillier.paillier_dec(N,m_paillierPub,m_paillierPrv,nFromSender);
//            m_paillierIO.writeToFile(N->m);
//            mpz_class NC(N->m);
//            NVector.push_back(NC);
//        }
//
//        m_paillierIO.sendFile();
//
//        for(int candidateIdx=0;candidateIdx<m_pCandidates.size();candidateIdx++)
//        {
//            mpz_t tempP;
//            mpz_init(tempP);
//            mpz_set(tempP,m_pCandidates[candidateIdx].get_mpz_t());
//            mpz_t tempQ;
//            mpz_init(tempQ);
//            mpz_set(tempQ,m_qCandidates[candidateIdx].get_mpz_t());
//            mpz_t tempN;
//            mpz_init(tempN);
//            mpz_set(tempN,NVector[candidateIdx].get_mpz_t());
//            sendPaillier(tempP);
//            sendPaillier(tempQ);
//            sendPaillier(tempN);
//        }*/
//
//}
//
//
//
//
//
//FdrPaillierParty2::FdrPaillierParty2(char *inputFilePath, char *outputFilePath,int commPortNumber) :
//        FdrPaillierParty(2,inputFilePath,outputFilePath,commPortNumber)
//{ }
//
//FdrPaillierParty2::~FdrPaillierParty2(){}
//
//void FdrPaillierParty2::run()
//{
//
//    mpz_t p;
//    mpz_t q;
//    mpz_t e1;
//    mpz_t e2;
//    mpz_t e3;
//    vector<mpz_class> e1Vector;
//    vector<mpz_class> e2Vector;
//    vector<mpz_class> e3Vector;
//
//    while(read(p)==0 && read(q)==0)
//    {
//        mpz_class cp(p);
//        m_pCandidates.push_back(cp);
//        mpz_class cq(q);
//        m_qCandidates.push_back(cq);
//    }
//
//    vector<string> dataFromSender;
//    receive(dataFromSender);
//    cout<<"element at idx 0 is : "<<dataFromSender[0]<<endl;
//
//
//    for(int candidateIdx=0;candidateIdx<m_pCandidates.size();candidateIdx++)
//    {
//        paillier_plaintext_t *e4M = new paillier_plaintext_t(); // M represents message
//        paillier_ciphertext_t *e4 = new paillier_ciphertext_t();
//
//        paillier_ciphertext_t * pCipher = new paillier_ciphertext_t();
//        paillier_ciphertext_t * qCipher = new paillier_ciphertext_t();
//
//
//        mpz_init(pCipher->c);
//        mpz_set(pCipher->c,p);
//        mpz_init(qCipher->c);
//        mpz_set(qCipher->c,q);
//
//
//        mpz_t pMultq;
//        mpz_init(pMultq);
//        mpz_mul(pMultq,m_pCandidates[candidateIdx].get_mpz_t(),m_qCandidates[candidateIdx].get_mpz_t());
//
//        mpz_init(e4M->m);
//        mpz_set(e4M->m,pMultq);
//
//
//        e4 = m_paillier.paillier_enc(e4,m_paillierPub,e4M,m_getRand);
//        m_encryptCounter++;
//
//        paillier_ciphertext_t *e1FromSender =  new paillier_ciphertext_t();
//        mpz_set(e1FromSender->c,e1);
//
//        paillier_ciphertext_t *e2FromSender =  new paillier_ciphertext_t();
//        mpz_set(e2FromSender->c,e2);
//
//
//        paillier_ciphertext_t *e3FromSender =  new paillier_ciphertext_t();
//        mpz_set(e3FromSender->c,e3);
//
//        //multiply results by constant;
//
//        paillier_ciphertext_t * q2Multe2 = multplyByConst(qCipher,e2FromSender);
//        paillier_ciphertext_t * p2Multe3 = multplyByConst(pCipher,e3FromSender);
//
//        paillier_ciphertext_t *e = new paillier_ciphertext_t();
//
//
//        m_paillier.paillier_mul(m_paillierPub,e,e1FromSender,q2Multe2);
//        m_paillier.paillier_mul(m_paillierPub,e,e,p2Multe3);
//        m_paillier.paillier_mul(m_paillierPub,e,e,e4);
//        m_addHomporphismCounter+=3;
//
//        //m_paillierIO.writePaillier(e->c);
//
//
//        /*
//        sendPaillier(e->c);
//
//        mpz_t N;
//        mpz_init(N);
//
//        receivePaillier(N);
//
//        write(N);
//        */
//
//    }
//
//    /*
//    m_paillierIO.sendFile();
//
//    mpz_t N;
//    vector<mpz_class> NVector;
//
//    while(m_paillierIO.readPaillier(N)==0)
//    {
//        mpz_class cn(N);
//        NVector.push_back(cn);
//    }
//
//    for(int candidateIdx=0;candidateIdx<m_pCandidates.size();candidateIdx++)
//    {
//        mpz_t tempP;
//        mpz_init(tempP);
//        mpz_set(tempP,m_pCandidates[candidateIdx].get_mpz_t());
//        mpz_t tempQ;
//        mpz_init(tempQ);
//        mpz_set(tempQ,m_qCandidates[candidateIdx].get_mpz_t());
//        mpz_t tempN;
//        mpz_init(tempN);
//        mpz_set(tempN,NVector[candidateIdx].get_mpz_t());
//        sendPaillier(tempP);
//        sendPaillier(tempQ);
//        sendPaillier(tempN);
//    }
//     */
//
//}
//
//paillier_ciphertext_t* FdrPaillierParty2::multplyByConst(paillier_ciphertext_t *op1, paillier_ciphertext_t *op2)
//{
//    m_multbyconst++;
//    paillier_ciphertext_t* eVector = m_paillier.paillier_create_enc_zero();
//    while(mpz_cmp_ui(op1->c,1)>0)
//    {
//        mpz_t ifOdd;
//        mpz_init(ifOdd);
//        mpz_mod_ui(ifOdd,op2->c,2);
//
//        if(mpz_cmp_ui(ifOdd,1)==0)
//        {
//            m_addHomporphismCounter++;
//            m_paillier.paillier_mul(m_paillierPub,eVector,op1,op2);
//        }
//
//        mpz_fdiv_q_2exp(op1->c,op1->c,1);
//        m_addHomporphismCounter++;
//        m_paillier.paillier_mul(m_paillierPub,op2,op2,op2);
//    }
//
//    return eVector;
//}
//
//
//
