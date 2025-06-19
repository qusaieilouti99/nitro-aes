import { NitroModules } from 'react-native-nitro-modules'
import type { AesNitro } from './specs/aes.nitro'

const NitroAes = NitroModules.createHybridObject<AesNitro>('NitroAes')

export default NitroAes
