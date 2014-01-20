package support;

import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;

import support.notaries.ICSI;
import support.notaries.Notary;
import util.ValidationResult;

public final class Service {
	private Service() { }

	private static Notary[] notaries = new Notary[] {
		new ICSI()
	};

	public static ValidationService getValidationService(
			final ExecutorService executorService) {
		return new ValidationService() {
			@Override
			public ValidationResult[] query(final Certificate certificate) {
				List<Callable<ValidationResult>> notaryQueries =
						new ArrayList<>(notaries.length);

				for (final Notary notary : notaries)
					notaryQueries.add(new Callable<ValidationResult>() {
						@Override
						public ValidationResult call() throws Exception {
							return notary.queryNotary(certificate);
						}
					});

				try {
					int i = 0;
					ValidationResult[] result = new ValidationResult[notaries.length];
					for (Future<ValidationResult> future : executorService.invokeAll(notaryQueries))
						result[i++] = future.get();
					return result;
				}
				catch (InterruptedException | ExecutionException e) {
					e.printStackTrace();
				}
				return new ValidationResult[] { ValidationResult.UNKNOWN };
			}
		};
	}

	public static ValidationService getValidationService() {
		return new ValidationService() {
			@Override
			public ValidationResult[] query(final Certificate certificate) {
				int i = 0;
				ValidationResult[] result = new ValidationResult[notaries.length];
				for (Notary notary : notaries)
					result[i++] = notary.queryNotary(certificate);

				return result;
			}
		};
	}
}
