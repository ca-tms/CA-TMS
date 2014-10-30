package services;

/**
 * Represents the result of a validation query
 */
final public class ValidationInformation {
	private final ValidationResult validationResult;
	private final ValidationResultSpec validationResultSpec;

	/**
	 * Creates a new <code>ValidationInformation</code> instance
	 * @param validationResult
	 * @param validationResultSpec
	 */
	public ValidationInformation(ValidationResult validationResult,
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
