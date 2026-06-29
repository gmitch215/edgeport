/**
 * @fileoverview Public re-export of the uniform error vocabulary.
 *
 * These are the only error types any edgeport protocol throws. Import them from the bare
 * entry point (`edgeport`) to branch on failures uniformly across protocols.
 *
 * @author Gregory Mitchell
 * @since 1.0.0
 */
export {
	AuthError,
	ConnectionError,
	EdgeportError,
	ProtocolError,
	TimeoutError,
	type EdgeportErrorOptions
} from './core/errors';
