package services.logic;

import util.ValidationResult;
import util.ValidationResultSpec;

/**
 * Represents the result of a validation query
 */
final public class ValidatorResult {
	private final ValidationResult validationResult;
	private final ValidationResultSpec validationResultSpec;

	/**
	 * Creates a new <code>ValidatorResult</code> instance
	 * @param validationResult
	 * @param validationResultSpec
	 */
	public ValidatorResult(ValidationResult validationResult,
			ValidationResultSpec validationResultSpec) {
		this.validationResult = validationResult;
		this.validationResultSpec = validationResultSpec;
	}

	/**
	 * @return the actual validation result
	 */
	public ValidationResult getValidationResult() {
		return validationResult;
	}

	/**
	 * @return the validation result specification
	 */
	public ValidationResultSpec getValidationResultSpec() {
		return validationResultSpec;
	}
}
