import { NitroModules } from 'react-native-nitro-modules'
import type { NitroAes as NitroAesSpec } from './specs/nitro-aes.nitro'

const NitroAes = NitroModules.createHybridObject<NitroAesSpec>('NitroAes')

export default NitroAes
