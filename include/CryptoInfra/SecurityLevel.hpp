#pragma once

/**
* Many cryptographic primitives and schemes have different security levels.
* For example, an encryption scheme can be CPA-secure (secure against chosen-plaintext attacks)
* or CCA-secure (secure against chosen-ciphertext attacks).
* The security level of a cryptographic entity is specified by making the implementing class of the entity
* declare that it implements a certain security level; for example, an encryption scheme that is CCA-secure will implement the Cca interface.
* Different primitives have different families that define their security levels (e.g., hash functions, MACs, encryption).
* It is often the case that different security levels of a given primitive form a hierarchy (e.g., any CCA-secure encryption scheme is also CPA-secure),
* and in this case they extend each other. Thus, it suffices to implement a Cca interface and this immediately implies that a Cpa interface is also implied.
* <p>
* All of the interfaces expressing a security level are marker interfaces that define types of security level and do not have any functionality.
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
*/
class SecurityLevel {};

/**
* This hierarchy specifies the security level of a cyclic group in which discrete log hardness is assumed to hold. The levels in this hierarchy are Dlog, CDH and DDH.
*/
class DlogSecLevel : public SecurityLevel {};

/**
* A group in which the discrete log problem is assumed to hold should implement this interface.
*/
class Dlog : public DlogSecLevel {};

/**
* A group in which the computational Diffie-Hellman problem is assumed to hold should implement this interface.
*/
class CDH:public Dlog {};

/**
* A group in which the decisional Diffie-Hellman problem is assumed to hold should implement this interface.
*/
class DDH : public CDH {};

/**
* This hierarchy specifies the security level of a cryptographic hash function. The levels in this hierarchy are TargetCollisionResistant and CollisionResistant.
*/
class HashSecLevel : public SecurityLevel {};

/**
* This hierarchy specifies the security level of a message authentication code (MAC) or digital signature scheme.<p>
* The hierarchy here only refers to the number of times that the MAC or signature scheme can be used; namely, OneTime or UnlimitedTimes.
* We do not currently have another interface for a bounded but not unlimited number of times; if necessary this can be added later.
* We also consider by default adaptive chosen-message attacks and so have not defined a separate hierarchy for adaptive/non-adaptive attacks and chosen versus random message attacs.
*/
class MacSignSecLevel : public SecurityLevel {};

/**
* Any MAC or signature scheme that is secure for one-time use only should implement this interface.
*/
class OneTime : public MacSignSecLevel {};
/**
* Any MAC or signature scheme that is secure for an unlimited number of uses should implement this interface. This is the security level of standard MAC and signature schemes.
*/
class UnlimitedTimes : public OneTime {};

/**
* This hierarchy specifies the security level of encryption schemes; it does not differentiate between symmetric and asymmetric encryption.
* There are two sub-hierarchies for encryption. The first relates to the adversarial power and includes Eav (eavesdropping adversary), CPA (chosen-plaintext attack),
* CCA1 (preprocessing chosen-ciphertext attack), and CCA2 (full chosen-ciphertext attack). The second relates to the aim of the attack and includes Indistinguishable (for the standard indistinguishability notion) and NonMalleable;
* note that non-malleability implies indistinguishability and thus the NonMalleable interface extends the Indistinguishable interface.
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
*
*/
class EncSecLevel : public SecurityLevel {};

/**
* An encryption scheme that is only secure for eavesdropping adversaries (like a stream cipher) should implement this interface.
* It is also necessary to specify if such a scheme is Indistinguishable or NonMalleable.
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
*
*/
class Eav : public EncSecLevel {};

/**
* An encryption scheme that is secure in the presence of chosen-plaintext attacks should implement this interface.
* It is also necessary to specify if such a scheme is Indistinguishable or NonMalleable.
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
*/

class Cpa : public Eav {};

/**
* This interface should be used when the security level of the encryption scheme is according to the regular indistinguishability game that defines privacy.
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
*/
class Indistinguishable : public EncSecLevel {};

/**
* This interface is the root interface of the security level hierarchy for (secure computation) protocols.<p>
* There are three different subhierarchies in this family. The first relates to the adversary's capabilities and includes
* Semihonest, Malicious and Covert. The second relates to the question of composition and includes StandAlone and UC (universally composable).
* The third relates to the corruption strategy of the adversary and includes AdaptiveWithErasures and AdaptiveNoErasures
* (if no interface here is implemented then static security is assumed).
*/
class ProtocolSecLevel : public SecurityLevel {};

class CommitSecLevel : public SecurityLevel {};
class SecureCommit : public CommitSecLevel {};
class StatisticallyHidingCmt : public SecureCommit {};
/**
* Any commitment scheme that is perfectly hiding should implement this interface.
*/
class PerfectlyHidingCmt : public StatisticallyHidingCmt {};
